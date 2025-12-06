// 温馨提示：绑定自定义域名后，需要在域名下左侧的网络菜单开启GRPC功能，否则不通

import { connect } from 'cloudflare:sockets'

const proxyIP = '13.230.34.30';  // proxyIP 用于访问cf cdn网站，例如chatgpt
const yourUUID = '5dc15e15-f285-4a9d-959b-0e4fbdd77b63'; // UUID

let cfip = [ 
    'mfa.gov.ua', 'saas.sin.fan', 'store.ubi.com','cf.130519.xyz','cf.008500.xyz', 
    'cf.090227.xyz', 'cf.877774.xyz','cdns.doon.eu.org','sub.danfeng.eu.org','cf.zhetengsha.eu.org'
]; 

let ACTIVE_CONNECTIONS = 0;
const BUFFER_SIZE = 512 * 1024;
const CONNECT_TIMEOUT_MS = 3000;
const IDLE_TIMEOUT_MS = 30000;
const MAX_RETRIES = 2;
const MAX_CONCURRENT = 64;
const activeConnections = new WeakMap();
const activeStreams = new WeakMap();
function get_buffer(size) { return new Uint8Array(size || BUFFER_SIZE) }
const ADDRESS_TYPE_IPV4 = 1, ADDRESS_TYPE_URL = 2, ADDRESS_TYPE_IPV6 = 3;
function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '')
    const r = []
    for (let i = 0; i < 16; i++) r.push(parseInt(uuid.substr(i * 2, 2), 16))
    return r
}

function validate_uuid(id, uuid) {
    for (let i = 0; i < 16; i++) if (id[i] !== uuid[i]) return false
    return true
}

function concat_typed_arrays(first, ...args) {
    let len = first.length
    for (let a of args) len += a.length
    const r = new first.constructor(len)
    r.set(first, 0)
    len = first.length
    for (let a of args) { r.set(a, len); len += a.length }
    return r
}

async function read_header(readable, uuid_str) {
    const reader = readable.getReader({ mode: 'byob' })
    try {
        let r = await reader.readAtLeast(1 + 16 + 1, get_buffer(1024))
        let rlen = 0
        let cache = r.value
        rlen += r.value.length
        const version = cache[0]
        const id = cache.slice(1, 17)
        const uuid = parse_uuid(uuid_str)
        if (!validate_uuid(id, uuid)) {
            reader.releaseLock();
            return null;
        }
        const pb_len = cache[17]
        const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1
        if (addr_plus1 + 1 > rlen) {
            if (r.done) {
                reader.releaseLock();
                return null;
            }
            r = await reader.readAtLeast(addr_plus1 + 1 - rlen, get_buffer(1024))
            rlen += r.value.length
            cache = concat_typed_arrays(cache, r.value)
        }
        const cmd = cache[1 + 16 + 1 + pb_len]
        if (cmd !== 1) {
            reader.releaseLock();
            return null;
        }
        const port = (cache[addr_plus1 - 3] << 8) + cache[addr_plus1 - 2]
        const atype = cache[addr_plus1 - 1]
        let header_len = -1
        if (atype === ADDRESS_TYPE_IPV4) header_len = addr_plus1 + 4
        else if (atype === ADDRESS_TYPE_IPV6) header_len = addr_plus1 + 16
        else if (atype === ADDRESS_TYPE_URL) header_len = addr_plus1 + 1 + cache[addr_plus1]
        if (header_len < 0) {
            reader.releaseLock();
            return null;
        }
        if (header_len > rlen) {
            r = await reader.readAtLeast(header_len - rlen, get_buffer(1024))
            rlen += r.value.length
            cache = concat_typed_arrays(cache, r.value)
        }
        let hostname = ''
        const idx = addr_plus1
        if (atype === ADDRESS_TYPE_IPV4) hostname = cache.slice(idx, idx + 4).join('.')
        else if (atype === ADDRESS_TYPE_URL) hostname = new TextDecoder().decode(cache.slice(idx + 1, idx + 1 + cache[idx]))
        else if (atype === ADDRESS_TYPE_IPV6) hostname = cache.slice(idx, idx + 16).reduce((s, b2, i2, a) => i2 % 2 ? s.concat(((a[i2 - 1] << 8) + b2).toString(16)) : s, []).join(':')
        if (!hostname) {
            reader.releaseLock();
            return null;
        }
        const data = cache.slice(header_len)
        return { hostname, port, data, resp: new Uint8Array([version, 0]), reader, done: r.done }
    } catch (e) {
        try { reader.releaseLock() } catch (_) { }
        throw e
    }
}
class Counter {
    #total;
    constructor() { this.#total = 0 }
    get() { return this.#total }
    add(size) { this.#total += size }
}

async function upload_to_remote(counter, writer, httpx) {
    const writeStreamRef = new WeakRef(writer);
    activeStreams.set(writer, { type: 'upload', timestamp: Date.now() });
    
    async function inner(d) { 
        if (!d || d.length === 0) return; 
        counter.add(d.length); 
        await writer.write(d); 
    }
    
    try {
        await inner(httpx.data)
        while (!httpx.done) {
            const r = await httpx.reader.read(get_buffer(16 * 1024))
            if (r.done) break
            await inner(r.value)
            httpx.done = r.done
        }
    } catch (e) {
        console.error('Upload error:', e.message);
        throw e;
    } finally {
        try { 
            httpx.reader.releaseLock(); 
        } catch (_) { 
            // ignore error
        }
        
        try {
            const stream = writeStreamRef.deref();
            if (stream) {
                activeStreams.delete(stream);
            }
        } catch (_) {
            // ignore error
        }
    }
}

function create_uploader(httpx, writable) {
    const counter = new Counter()
    const writer = writable.getWriter()
    const done = (async () => {
        try {
            await upload_to_remote(counter, writer, httpx)
        } catch (e) {
            try { writer.abort() } catch (_) { }
            throw e;
        } finally {
            try { await writer.close() } catch (_) { }
        }
    })()
    return { counter, done, abort: () => { try { writer.abort() } catch (_) { } } }
}

function create_downloader(resp, remote_readable) {
    const counter = new Counter()
    let stream
    const done = new Promise((resolve, reject) => {
        stream = new TransformStream({
            start(c) { counter.add(resp.length); c.enqueue(resp) },
            transform(chunk, c) { counter.add(chunk.length); c.enqueue(chunk) },
            cancel(reason) { reject(reason) }
        }, null, new ByteLengthQueuingStrategy({ highWaterMark: BUFFER_SIZE }))

        const reader = remote_readable.getReader()
        const writer = stream.writable.getWriter()
        activeStreams.set(reader, { type: 'download_reader', timestamp: Date.now() });
        activeStreams.set(writer, { type: 'download_writer', timestamp: Date.now() });

        ; (async () => {
            try {
                while (true) {
                    const r = await reader.read()
                    if (r.done) break
                    await writer.write(r.value)
                }
                await writer.close()
                resolve()
            } catch (e) {
                reject(e)
            } finally {
                try { reader.releaseLock() } catch (_) {}
                try { writer.releaseLock() } catch (_) {}
                
                try {
                    activeStreams.delete(reader);
                    activeStreams.delete(writer);
                } catch (_) {
                    // ignore error
                }
            }
        })()
    })
    return {
        readable: stream.readable,
        counter,
        done,
        abort: () => {
            try { stream.readable.cancel() } catch (_) { }
            try { stream.writable.abort() } catch (_) { }
        }
    }
}

function parseProxyConfig(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();
    if (proxyStr.startsWith('socks://') || proxyStr.startsWith('socks5://')) {
        const urlStr = proxyStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : '',
                host: url.hostname,
                port: parseInt(url.port) || 1080
            };
        } catch (e) {
            const socksMatch = proxyStr.match(/^socks5?:\/\/(?:([^:]+):([^@]+)@)?([^:]+)(?::(\d+))?$/);
            if (socksMatch) {
                return {
                    type: 'socks5',
                    username: socksMatch[1] || '',
                    password: socksMatch[2] || '',
                    host: socksMatch[3],
                    port: parseInt(socksMatch[4]) || 1080
                };
            }
            return null;
        }
    }
    if (proxyStr.startsWith('http://') || proxyStr.startsWith('https://')) {
        try {
            const url = new URL(proxyStr);
            return {
                type: url.protocol === 'https:' ? 'https' : 'http',
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : '',
                host: url.hostname,
                port: parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80)
            };
        } catch (e) {
            const httpMatch = proxyStr.match(/^(https?):\/\/(?:([^:]+):([^@]+)@)?([^:]+)(?::(\d+))?$/);
            if (httpMatch) {
                return {
                    type: httpMatch[1],
                    username: httpMatch[2] || '',
                    password: httpMatch[3] || '',
                    host: httpMatch[4],
                    port: parseInt(httpMatch[5]) || (httpMatch[1] === 'https' ? 443 : 80)
                };
            }
            return null;
        }
    }
    const hostMatch = proxyStr.match(/^([^:]+)(?::(\d+))?$/);
    if (hostMatch) {
        return {
            type: 'direct',
            host: hostMatch[1],
            port: parseInt(hostMatch[2] || '443')
        };
    }
    return null;
}

async function socks5Connect(remote, targetHost, targetPort, username, password) {
    let writer, reader;
    try {
        writer = remote.writable.getWriter();
        const hasAuth = username && password;
        const authMethods = hasAuth ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]); 
        
        await writer.write(authMethods);
        writer.releaseLock();
        
        reader = remote.readable.getReader();
        const authResponse = await reader.read();
        if (authResponse.done || authResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        
        const selectedMethod = new Uint8Array(authResponse.value)[1];
        reader.releaseLock();
        
        if (selectedMethod === 0x02) {
            if (!username || !password) {
                throw new Error('S5 requires authentication');
            }
            const writer2 = remote.writable.getWriter();
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; 
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            await writer2.write(authPacket);
            writer2.releaseLock();
            
            const reader2 = remote.readable.getReader();
            const authResponse2 = await reader2.read();
            if (authResponse2.done || new Uint8Array(authResponse2.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
            reader2.releaseLock();
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        
        const writer3 = remote.writable.getWriter();
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00; 
        connectPacket[3] = 0x03; 
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer3.write(connectPacket);
        writer3.releaseLock();
        
        const reader3 = remote.readable.getReader();
        const connectResponse = await reader3.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        reader3.releaseLock();
        return true;
    } catch (e) {
        try { if (writer) writer.releaseLock(); } catch (_) {}
        try { if (reader) reader.releaseLock(); } catch (_) {}
        throw new Error(`s5 error: ${e.message}`);
    }
}

async function httpConnect(remote, targetHost, targetPort, username, password) {
    let writer, reader;
    try {
        writer = remote.writable.getWriter();
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        connectRequest += '\r\n';
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
        reader = remote.readable.getReader();
        let responseData = new Uint8Array(0);
        let headerComplete = false;
        const readTimeout = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('HTTP read timeout')), CONNECT_TIMEOUT_MS)
        );
        
        while (!headerComplete) {
            const chunk = await Promise.race([
                reader.read(),
                readTimeout
            ]);
            
            if (chunk.done) {
                throw new Error('HTTP connection closed unexpectedly');
            }
            
            const newData = new Uint8Array(responseData.length + chunk.value.byteLength);
            newData.set(responseData);
            newData.set(new Uint8Array(chunk.value), responseData.length);
            responseData = newData;
            
            const responseText = new TextDecoder().decode(responseData);
            if (responseText.includes('\r\n\r\n')) {
                headerComplete = true;
            }
        }
        reader.releaseLock();
        
        const responseText = new TextDecoder().decode(responseData);
        if (!responseText.startsWith('HTTP/1.1 200') && !responseText.startsWith('HTTP/1.0 200')) {
            throw new Error(`HTTP connection failed: ${responseText.split('\r\n')[0]}`);
        }
        return true;
    } catch (e) {
        try { if (writer) writer.releaseLock(); } catch (_) {}
        try { if (reader) reader.releaseLock(); } catch (_) {}
        throw new Error(`HTTP connection failed: ${e.message}`);
    }
}

async function connect_to_remote(httpx, proxyIP, fallbackProxyIP) {
    const proxyConfig = parseProxyConfig(proxyIP);
    
    if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
        let remote = null;
        try {
            remote = connect({ hostname: proxyConfig.host, port: proxyConfig.port });
            activeConnections.set(remote, { 
                type: proxyConfig.type, 
                host: proxyConfig.host, 
                port: proxyConfig.port,
                timestamp: Date.now() 
            });
        
            await Promise.race([
                remote.opened,
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error(`connet ${proxyConfig.host}:${proxyConfig.port} timeout`)), CONNECT_TIMEOUT_MS)
                )
            ]);
            
            if (proxyConfig.type === 'socks5') {
                await socks5Connect(remote, httpx.hostname, httpx.port, proxyConfig.username, proxyConfig.password);
            } else {
                await httpConnect(remote, httpx.hostname, httpx.port, proxyConfig.username, proxyConfig.password);
            }
            
            const uploader = create_uploader(httpx, remote.writable);
            const downloader = create_downloader(httpx.resp, remote.readable);
            return {
                downloader,
                uploader,
                close: () => { 
                    try { 
                        activeConnections.delete(remote);
                        remote.close(); 
                    } catch (_) { 
                        // ignore error
                    } 
                }
            };
        } catch (e) {
            if (remote) {
                try { 
                    activeConnections.delete(remote);
                    remote.close(); 
                } catch (_) { 
                    // ignore error
                }
            }
            console.error(`${proxyConfig.type.toUpperCase()} connet failed:`, e.message);
            return null;
        }
    }
    
    const connectionTargets = [
        { type: "direct", host: httpx.hostname, port: httpx.port },
        { type: "proxy", host: proxyConfig ? proxyConfig.host : proxyIP, port: proxyConfig ? proxyConfig.port : httpx.port },
        { type: "fallback", host: fallbackProxyIP, port: httpx.port }
    ].filter(target => target.host);

    const connectionPromises = connectionTargets.map(({ type, host, port }) =>
        (async () => {
            let remote = null;
            for (let attempt = 0; attempt < MAX_RETRIES + 1; attempt++) {
                try {
                    remote = connect({ hostname: host, port: port });
                    activeConnections.set(remote, { 
                        type, 
                        host, 
                        port,
                        timestamp: Date.now(),
                        attempt
                    });
                
                    await Promise.race([
                        remote.opened,
                        new Promise((_, reject) => 
                            setTimeout(() => reject(new Error(` ${host} timeout`)), CONNECT_TIMEOUT_MS)
                        )
                    ]);
                    return { remote, host, type };
                } catch (error) {
                    if (remote) {
                        try { 
                            activeConnections.delete(remote);
                            remote.close(); 
                        } catch (_) { 
                            // ignore error
                        }
                    }
                    
                    if (attempt < MAX_RETRIES) {
                        await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
                        continue;
                    }
                    throw error;
                }
            }
        })()
    );

    let successfulConnection = null;
    const results = await Promise.allSettled(connectionPromises);
    
    for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
            successfulConnection = result.value;
            break;
        }
    }

    if (successfulConnection) {
        const { remote } = successfulConnection;
        const uploader = create_uploader(httpx, remote.writable);
        const downloader = create_downloader(httpx.resp, remote.readable);
        return {
            downloader,
            uploader,
            close: () => { 
                try { 
                    activeConnections.delete(remote);
                    remote.close(); 
                } catch (_) { 
                    // ignore error
                } 
            }
        };
    } else {
        return null;
    }
}

async function handle_client(body, cfg) {
    if (ACTIVE_CONNECTIONS >= MAX_CONCURRENT) {
        return new Response('Too many connections', { status: 429 });
    }
    
    ACTIVE_CONNECTIONS++;
    let cleaned = false;
    
    const cleanup = () => {
        if (!cleaned) {
            ACTIVE_CONNECTIONS = Math.max(0, ACTIVE_CONNECTIONS - 1);
            cleaned = true;
        }
    };

    try {
        const httpx = await read_header(body, cfg.UUID);
        if (!httpx) {
            cleanup();
            return null;
        }
        
        const remoteConnection = await connect_to_remote(httpx, cfg.PROXYIP, '13.230.34.30');
        if (!remoteConnection) {
            cleanup();
            return null;
        }

        const connectionClosed = Promise.race([
            remoteConnection.downloader.done.catch(() => { }),
            remoteConnection.uploader.done.catch(() => { }),
            new Promise(resolve => setTimeout(resolve, IDLE_TIMEOUT_MS))
        ]).finally(() => {
            try { remoteConnection.close(); } catch (_) { }
            try { remoteConnection.downloader.abort(); } catch (_) { }
            try { remoteConnection.uploader.abort(); } catch (_) { }
            cleanup();
        });

        return { 
            readable: remoteConnection.downloader.readable, 
            closed: connectionClosed 
        };
    } catch (e) {
        console.error('Client handling error:', e.message);
        cleanup();
        return null;
    }
}

async function handle_post(request, cfg) {
    try {
        return await handle_client(request.body, cfg);
    } catch (e) {
        console.error('POST handling error:', e.message);
        return null;
    }
}

function generate_link(uuid, hostname, port, path, sni, currentHost, proxyIP = null) {
    const protc = 'x'+'h'+'t'+'t'+'p', header = 'v'+'l'+'e'+'s'+'s';
    const params = new URLSearchParams({
        encryption: 'none', security: 'tls', sni: sni || currentHost, fp: 'chrome', allowInsecure: '1', alpn: 'h2,http/1.1',
        type: protc, host: currentHost, path: path.startsWith('/') ? path : `/${path}`, mode: 'stream-one'
    })
    
    if (proxyIP) {
        params.append('proxyip', proxyIP);
    }
    
    return `${header}://${uuid}@${hostname}:${port}?${params.toString()}#${header}-${protc}`
}

function generate_subscription(uuid, cfipList, port = 443, path, sni, currentHost, proxyIP = null) {
    return btoa(cfipList.map(h => generate_link(uuid, h, port, path, sni, currentHost, proxyIP)).join('\n'))
}

export default {
    async fetch(request) {
        const url = new URL(request.url)
        let customProxyIP = proxyIP;
        let pathProxyIP = null;
        let pathname = url.pathname;
        if (pathname.startsWith('/proxyip=')) {
            try { pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
            } catch (e) { }
        }
        customProxyIP = pathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip') || proxyIP;
        const cfg = { UUID: yourUUID, PROXYIP: customProxyIP }
        if (request.method === 'POST') {
            const r = await handle_post(request, cfg)
            if (r) return new Response(r.readable, {
                headers: {
                    'X-Accel-Buffering': 'no',
                    'Cache-Control': 'no-store',
                    Connection: 'keep-alive',
                    'User-Agent': 'Go-http-client/2.0',
                    'Content-Type': 'application/grpc'
                }
            })
            return new Response('Internal Server Error', { status: 500 })
        }
        if (request.method === 'GET') {
            const path = url.pathname
            if (path === '/') {
                return new Response(
                    `<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS XHTTP</title><style>body{font-family:Arial,sans-serif;background:linear-gradient(135deg, #85dfb5 0%, #136e92 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}.container{max-width:600px;background:#fff;padding:40px;border-radius:10px;box-shadow:0 10px 40px rgba(0,0,0,.3);text-align:center}h1{color:#667eea;margin-bottom:20px}.info{font-size:18px;color:#666;margin:20px 0}.link{display:inline-block;background:#667eea;color:#fff;padding:12px 30px;border-radius:5px;text-decoration:none;margin-top:20px}.link:hover{background:#5568d3}.footer{margin-top:30px;padding-top:20px;border-top:1px solid #eee;font-size:14px;color:#999}.footer a{color:#667eea;text-decoration:none;margin:0 10px}.footer a:hover{text-decoration:underline}</style></head><body><div class="container"><h2>VLESS-XHTTP 代理服务</h2><div class="info">请访问: <strong>https://${url.hostname}/你的UUID</strong><br><br><p>查看节点订阅链接</p><div class="footer"><a href="https://github.com/eooce/CF-Workers-and-Snip-VLESS" target="_blank">GitHub 项目</a>|<a href="https://t.me/eooceu" target="_blank">Telegram 群组</a>|<a href="https://check-proxyip.ssss.nyc.mn" target="_blank">ProxyIP 检测服务</a></div></div></body></html>`,
                    { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
                );
            }
            if (path.includes(cfg.UUID) && path.toLowerCase() !== `/sub/${yourUUID}`) {
                return new Response(
                    `<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS XHTTP</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;background:linear-gradient(135deg, #85dfb5 0%, #136e92 100%);min-height:100vh;padding:20px}.container{max-width:900px;margin:0 auto;background:#fff;border-radius:15px;padding:30px;box-shadow:0 20px 60px rgba(0,0,0,.3)}h1{color:#667eea;margin-bottom:10px;font-size:2rem;text-align:center}.section{margin-bottom:25px}.section-title{color:#667eea;font-size:16px;font-weight:600;margin-bottom:12px;padding-bottom:6px;border-bottom:2px solid #667eea}.link-box{background:#f7f9fc;border:1px solid #e1e8ed;border-radius:8px;padding:12px;margin-bottom:10px}.link-label{font-size:16px;color:#666;margin-bottom:6px;font-weight:700}.link-content{display:flex;gap:8px}.link-text{flex:1;background:#fff;padding:8px 12px;border-radius:5px;border:1px solid #ddd;font-size:.8rem;word-break:break-all;font-family:monospace}.copy-btn{background:#667eea;color:#fff;border:none;padding:8px 16px;border-radius:5px;cursor:pointer;font-size:13px;white-space:nowrap}.copy-btn:hover{background:#5568d3}.copy-btn.copied{background:#48c774}.usage-section{background:#fff9e6;border-left:4px solid #ffc107;padding:15px;border-radius:5px;margin-top:25px}.usage-title{color:#f57c00;font-size:1.2rem;font-weight:600;margin-bottom:12px}.usage-item{margin-bottom:12px;font-size:13px;line-height:1.6}.usage-item strong{color:#333;display:block;margin-bottom:4px}.usage-item code{background:#fff;padding:2px 6px;border-radius:3px;color:#e91e63;font-size:13px;border:1px solid #ddd;word-wrap:break-word;word-break:break-all;display:inline-block;max-width:100%}.example{color:#666;font-size:14px;margin-left:8px}.footer{margin-top:30px;padding-top:20px;border-top:1px solid #e1e8ed;text-align:center;font-size:14px;color:#999}.footer a{color:#667eea;text-decoration:none;margin:0 10px}.footer a:hover{text-decoration:underline}@media (max-width:768px){.container{padding:20px}.link-content{flex-direction:column}.copy-btn{width:100%}}</style></head><body><div class="container"><h1>VLESS-XHTTP 订阅中心</h1><br><div class="section"><div class="section-title">🔗 通用订阅</div><div class="link-box"><div class="link-label">v2rayN / Loon / Shadowrocket / Karing</div><div class="link-content"><div class="link-text" id="v2ray-link">https://${url.hostname}/sub/${yourUUID}</div><button class="copy-btn" onclick="copyToClipboard('v2ray-link',this)">复制</button></div></div></div><div class="usage-section"><div class="usage-title">⚙️ 自定义路径(节点里的path)使用说明</div><div class="usage-item"><strong>1. 默认路径</strong><code>/</code><div class="example">使用代码里设置的默认proxyip</div></div><div class="usage-item"><strong>2. 带端口的proxyip</strong><code>/proxyip=210.61.97.241:81</code><br><code>/proxyip=proxy.xxxxxxxx.tk:50001</code></div><div class="usage-item"><strong>3. 域名proxyip</strong><code>/proxyip=jp.yutian.nyc.mn</code></div><div class="usage-item"><strong>4. 全局SOCKS5</strong><code>/proxyip=socks://user:password@host:port</code><br><code>/proxyip=socks5://user:password@host:port</code></div><div class="usage-item"><strong>5. 全局HTTP/HTTPS</strong><code>/proxyip=http://user:password@host:port</code><br><code>/proxyip=https://user:password@host:port</code></div></div><div class="footer"><a href="https://github.com/eooce/CF-Workers-and-Snip-VLESS" target="_blank">GitHub 项目</a>|<a href="https://t.me/eooceu" target="_blank">Telegram 群组</a>|<a href="https://check-proxyip.ssss.nyc.mn" target="_blank">ProxyIP 检测服务</a></div></div><script>function copyToClipboard(e,t){const n=document.getElementById(e).textContent;navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(n).then(()=>{showCopySuccess(t)}).catch(()=>{fallbackCopy(n,t)}):fallbackCopy(n,t)}function fallbackCopy(e,t){const n=document.createElement("textarea");n.value=e,n.style.position="fixed",n.style.left="-999999px",document.body.appendChild(n),n.select();try{document.execCommand("copy"),showCopySuccess(t)}catch(e){alert("复制失败，请手动复制")}document.body.removeChild(n)}function showCopySuccess(e){const t=e.textContent;e.textContent="已复制",e.classList.add("copied"),setTimeout(()=>{e.textContent=t,e.classList.remove("copied")},2e3)}</script></body></html>`,
                    { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
                );
            }
            if (path.toLowerCase() === `/sub/${yourUUID}`) {
                const port = 443,
                    nodePath = '/',
                    sni = url.searchParams.get('sni') || url.hostname,
                    currentHost = url.hostname
                const subscription = generate_subscription(cfg.UUID, cfip, port, nodePath, sni, currentHost, cfg.PROXYIP)
                return new Response(subscription, {
                    headers: {
                        'Content-Type': 'text/plain; charset=utf-8',
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'Expires': '0'
                    }
                })
            }
        }
        return new Response('Method Not Allowed', { status: 405 })
    }
}
