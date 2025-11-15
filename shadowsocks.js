// 如需要使用环境变量,将119至224行取消注释

import { connect } from 'cloudflare:sockets';

let subPath = 'link';     // 节点订阅路径,不修改将使用UUID作为订阅路径
let proxyIP = '13.230.34.30';  // proxyIP 格式：ip、域名、ip:port、域名:port等,没填写port，默认使用443
let password = '5dc15e15-f285-4a9d-959b-0e4fbdd77b63';  // 节点UUID

// CF CDN 
let cfip = [ // 格式:优选域名:端口#备注名称、优选IP:端口#备注名称、[ipv6优选]:端口#备注名称、优选域名#备注 
    'mfa.gov.ua#SG', 'saas.sin.fan#JP', 'store.ubi.com#SG','cf.130519.xyz#KR','cf.008500.xyz#HK', 
    'cf.090227.xyz#SG', 'cf.877774.xyz#HK','cdns.doon.eu.org#JP','sub.danfeng.eu.org#TW','cf.zhetengsha.eu.org#HK'
];  // 在此感谢各位大佬维护的优选域名

function closeSocketQuietly(socket) { 
    try { 
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close(); 
        }
    } catch (error) {} 
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try { 
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null }; 
    } catch (error) { 
        return { error }; 
    }
}

function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }

    const lastColonIndex = serverStr.lastIndexOf(':');
    
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const portStr = serverStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    
    return { type: 'direct', host: serverStr, port: 443 };
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com', 'ovo.speedtestcustom.com'];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }

    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

export default {
    async fetch(request,env) {
        try {
            // workers 部署，需要环境变量，把下面5行前面的//去掉，取消注释即可使用对应的环境变量
            // if (env.PROXYIP || env.proxyip || env.proxyIP) {
            //     const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
            //     proxyIP = servers[0]; 
            // }
            // password = env.PASSWORD || env.password || env.uuid || env.UUID || password;
            // subPath = env.SUB_PATH || env.subpath || subPath;

            if (subPath === 'link' || subPath === '') {
                subPath = password;
            }
            const servers = proxyIP.split(',').map(s => s.trim());
            proxyIP = servers[0]; 

            const method = 'none';
            const url = new URL(request.url);
            const pathname = url.pathname;
            
            let pathProxyIP = null;
            if (pathname.startsWith('/proxyip=')) {
                try {
                    pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                } catch (e) {
                    // 忽略错误
                }

                if (pathProxyIP && !request.headers.get('Upgrade')) {
                    proxyIP = pathProxyIP;
                    return new Response(`set proxyIP to: ${proxyIP}\n\n`, {
                        headers: { 
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }

            if (request.headers.get('Upgrade') === 'websocket') {
                let wsPathProxyIP = null;
                if (pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    } catch (e) {
                        // 忽略错误
                    }
                }
                
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip');
                return await handleSSRequest(request, customProxyIP);
            } else if (request.method === 'GET') {
                if (url.pathname === '/') {
                    return getSimplePage(request);
                }
                
                if (url.pathname.toLowerCase() === `/${password.toLowerCase()}`) {
                    return getHomePage(request);
                }
                
                // 订阅路径 /sub/UUID
                if (url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}` || url.pathname.toLowerCase() === `/sub/${subPath.toLowerCase()}/`) {
                    const currentDomain = url.hostname;
                    const ssHeader = 's'+'s';
                    const ssLinks = cfip.map(cdnItem => {
                        let host, port = 443, nodeName = '';
                        if (cdnItem.includes('#')) {
                            const parts = cdnItem.split('#');
                            cdnItem = parts[0];
                            nodeName = parts[1];
                        }

                        if (cdnItem.startsWith('[') && cdnItem.includes(']:')) {
                            const ipv6End = cdnItem.indexOf(']:');
                            host = cdnItem.substring(0, ipv6End + 1); 
                            const portStr = cdnItem.substring(ipv6End + 2); 
                            port = parseInt(portStr) || 443;
                        } else if (cdnItem.includes(':')) {
                            const parts = cdnItem.split(':');
                            host = parts[0];
                            port = parseInt(parts[1]) || 443;
                        } else {
                            host = cdnItem;
                        }
                        
                        const ssConfig = `${method}:${password}@${host}:${port}`;
                        const ssNodeName = nodeName ? `${nodeName}-${ssHeader}` : `${ssHeader}`;
                        const encodedConfig = btoa(ssConfig);
                        const v2rayPluginObj = {
                            tls: true,
                            mux: false,
                            mode: "websocket",
                            allowInsecure: true,
                            host: currentDomain,
                            peer: currentDomain,
                            path: "/?ed=2560"
                        };
                        const v2rayPluginStr = JSON.stringify(v2rayPluginObj);
                        const encodedV2rayPlugin = btoa(v2rayPluginStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                        return `${ssHeader}://${encodedConfig}?v2ray-plugin=${encodedV2rayPlugin}#${ssNodeName}`;
                    });
                    
                    const linksText = ssLinks.join('\n');
                    const base64Content = btoa(unescape(encodeURIComponent(linksText)));
                    return new Response(base64Content, {
                        headers: { 
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }
            return new Response('Not Found', { status: 404 });
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};

async function handleSSRequest(request, customProxyIP) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            
            const { hasError, message, addressType, port, hostname, rawIndex } = parseSSPacketHeader(chunk);
            if (hasError) throw new Error(message);

            if (isSpeedTestSite(hostname)) {
                throw new Error('Speedtest site is blocked');
            }

            if (addressType === 2) { 
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            
            const rawData = chunk.slice(rawIndex);
            if (isDnsQuery) return forwardataudp(rawData, serverSock, null);
            await forwardataTCP(hostname, port, rawData, serverSock, null, remoteConnWrapper, customProxyIP);
        },
    })).catch((err) => {
        // console.error('Readable pipe error:', err);
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}

function parseSSPacketHeader(chunk) {
    if (chunk.byteLength < 7) return { hasError: true, message: 'Invalid data' };
    
    try {
        const view = new Uint8Array(chunk);
        const addressType = view[0];
        let addrIdx = 1, addrLen = 0, addrValIdx = addrIdx, hostname = '';
        
        switch (addressType) {
            case 1: // IPv4
                addrLen = 4; 
                hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); 
                addrValIdx += addrLen;
                break;
            case 3: // Domain
                addrLen = view[addrIdx];
                addrValIdx += 1; 
                hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                addrValIdx += addrLen;
                break;
            case 4: // IPv6
                addrLen = 16; 
                const ipv6 = []; 
                const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); 
                hostname = ipv6.join(':'); 
                addrValIdx += addrLen;
                break;
            default: 
                return { hasError: true, message: `Invalid address type: ${addressType}` };
        }
        
        if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
        
        const port = new DataView(chunk.slice(addrValIdx, addrValIdx + 2)).getUint16(0);
        return { hasError: false, addressType, port, hostname, rawIndex: addrValIdx + 2 };
    } catch (e) {
        return { hasError: true, message: 'Failed to parse SS packet header' };
    }
}

async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        const authMethods = username && password ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]); 
        
        await writer.write(authMethods);
        const methodResponse = await reader.read();
        if (methodResponse.done || methodResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        
        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) {
                throw new Error('S5 requires authentication');
            }
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; 
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            await writer.write(authPacket);
            const authResponse = await reader.read();
            if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00; 
        connectPacket[3] = 0x03; 
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer.write(connectPacket);
        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        writer.releaseLock();
        reader.releaseLock();
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        
        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        
        connectRequest += `User-Agent: Mozilla/5.0\r\n`;
        connectRequest += `Connection: keep-alive\r\n`;
        connectRequest += '\r\n';
        await writer.write(new TextEncoder().encode(connectRequest));
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        let bytesRead = 0;
        const maxHeaderSize = 8192;
        
        while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) {
                throw new Error('Connection closed before receiving HTTP response');
            }
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            bytesRead = responseBuffer.length;
            
            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                    responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }
        
        if (headerEndIndex === -1) {
            throw new Error('Invalid HTTP response');
        }
        
        const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
        const statusLine = headerText.split('\r\n')[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        
        if (!statusMatch) {
            throw new Error(`Invalid response: ${statusLine}`);
        }
        
        const statusCode = parseInt(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`Connection failed: ${statusLine}`);
        }
        
        console.log('HTTP connection established for Shadowsocks');
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        
        return socket;
    } catch (error) {
        try { 
            writer.releaseLock(); 
        } catch (e) {}
        try { 
            reader.releaseLock(); 
        } catch (e) {}
        try { 
            socket.close(); 
        } catch (e) {}
        throw error;
    }
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP) {
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    
    let proxyConfig = null;
    let shouldUseProxy = false;
    if (customProxyIP) {
        proxyConfig = parsePryAddress(customProxyIP);
        if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
            shouldUseProxy = true;
        } else if (!proxyConfig) {
            proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        }
    } else {
        proxyConfig = parsePryAddress(proxyIP) || { type: 'direct', host: proxyIP, port: 443 };
        if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            shouldUseProxy = true;
        }
    }
    
    async function connecttoPry() {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        }
        
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }
    
    if (shouldUseProxy) {
        try {
            await connecttoPry();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);
        } catch (err) {
            await connecttoPry();
        }
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => { 
                if (!cancelled) controller.enqueue(event.data); 
            });
            socket.addEventListener('close', () => { 
                if (!cancelled) { 
                    closeSocketQuietly(socket); 
                    controller.close(); 
                } 
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error); 
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { 
            cancelled = true; 
            closeSocketQuietly(socket); 
        }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
                if (header) { 
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer); 
                    header = null; 
                } else { 
                    webSocket.send(chunk); 
                }
            },
            abort() {},
        })
    ).catch((err) => { 
        closeSocketQuietly(webSocket); 
    });
    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) { 
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null; 
                    } else { 
                        webSocket.send(chunk); 
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}

function getHomePage(request) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Shadowsocks Service</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;margin:0;padding:0;overflow:hidden;}.container{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:20px;padding:20px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:800px;width:95%;text-align:center;}.logo{margin-bottom:20px;}.title{font-size:2rem;margin-bottom:10px;color:#2d3748;}.subtitle{color:#718096;margin-bottom:30px;font-size:1.1rem;}.info-card{background:#f7fafc;border-radius:12px;padding:20px;margin:20px 0;text-align:left;border-left:4px solid #6ed8c9;}.info-item{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #e2e8f0;}.info-item:last-child{border-bottom:none;}.label{font-weight:600;color:#4a5568;}.value{color:#2d3748;font-family:'Courier New',monospace;background:#edf2f7;padding:4px 8px;border-radius:4px;font-size:0.9rem;}.button-group{display:flex;gap:15px;justify-content:center;flex-wrap:wrap;margin:30px 0;}.btn{padding:12px 24px;background:linear-gradient(135deg,#12cd9e 0%,#a881d0 100%);color:white;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:all 0.3s ease;text-decoration:none;display:inline-block;}.btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,0.1);}.footer{margin-top:30px;color:#ef0202;font-size:0.9rem;}@media (max-width:768px){.container{padding:20px;}.button-group{flex-direction:column;align-items:center;}.btn{width:100%;max-width:300px;}}</style></head><body><div class="container"><div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo" width="96" height="96"></div><h1 class="title">Cloudflare Shadowsocks Service</h1><p class="subtitle">基于 Cloudflare 的高性能 Shadowsocks 代理服务</p><div class="info-card"><div class="info-item"><span class="label">服务状态</span><span class="value">运行中</span></div><div class="info-item"><span class="label">HOST地址</span><span class="value">${url}</span></div><div class="info-item"><span class="label">UUID</span><span class="value">${password}</span></div><div class="info-item"><span class="label">v2rayN/shadowrocket订阅地址</span><span class="value">${baseUrl}/sub/${password}</span></div></div><div class="button-group"><button onclick="copySubscription()" class="btn">复制订阅链接</button><button onclick="showQRCode()" class="btn">显示订阅二维码</button></div><div class="footer"><p>注意：v2rayN导入的节点链接参数不完整,需要手动补全</p><p style="margin-top: 20px;"><a href="https://github.com/danfeng-ss/Cloudflare-Shadowsocks-Worker" target="_blank" style="color: #718096; text-decoration: none; margin: 0 10px;">GitHub项目</a><a href="https://ip.skk.moe/" target="_blank" style="color: #718096; text-decoration: none; margin: 0 10px;">Proxyip检测</a><a href="https://t.me/eooceu" target="_blank" style="color: #718096; text-decoration: none; margin: 0 10px;">Telegram交流群</a></p></div></div><div id="qrModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background-color:rgba(0,0,0,0.5);z-index:1000;"><div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:20px;border-radius:10px;text-align:center;"><h2>Shadowrocket订阅二维码</h2><img id="qrCodeImage" src="" alt="QR Code" style="max-width:300px;height:auto;padding:10px;"><p style="word-break:break-all;"><a id="qrCodeLink" href="" target="_blank"></a></p><button onclick="closeQRModal()" style="margin-top:20px;padding:10px 20px;background:#12cd9e;color:white;border:none;border-radius:5px;cursor:pointer;">关闭</button></div></div><script>function copySubscription(){const configUrl='${baseUrl}/sub/${password}';navigator.clipboard.writeText(configUrl).then(()=>{alert('订阅链接已复制到剪贴板!');}).catch(()=>{const textArea=document.createElement('textarea');textArea.value=configUrl;document.body.appendChild(textArea);textArea.select();document.execCommand('copy');document.body.removeChild(textArea);alert('订阅链接已复制到剪贴板!');});}function showQRCode(){const configUrl='${baseUrl}/sub/${password}';document.getElementById('qrCodeImage').src='';document.getElementById('qrCodeLink').href='';document.getElementById('qrCodeLink').textContent='二维码生成中...';document.getElementById('qrModal').style.display='block';const qrUrl='https://tool.oschina.net/action/qrcode/generate?data='+encodeURIComponent(configUrl)+'&output=image%2Fpng&error=L&type=0&margin=4&size=4';fetch(qrUrl).then(response=>response.blob()).then(blob=>{const imageUrl=URL.createObjectURL(blob);document.getElementById('qrCodeImage').src=imageUrl;document.getElementById('qrCodeLink').href=configUrl;document.getElementById('qrCodeLink').textContent=configUrl;}).catch(()=>{document.getElementById('qrCodeImage').src=qrUrl;document.getElementById('qrCodeLink').href=configUrl;document.getElementById('qrCodeLink').textContent=configUrl;});}function closeQRModal(){document.getElementById('qrModal').style.display='none';}</script></body></html>`;
    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

function getSimplePage(request) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Shadowsocks Cloudflare Service</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;margin:0;padding:0;overflow:hidden;}.container{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:20px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:800px;width:95%;text-align:center;}.logo{margin-bottom:20px;}.title{font-size:2rem;margin-bottom:30px;color:#2d3748;}.tip-card{background:#fff3cd;border-radius:12px;padding:20px;margin:20px 0;text-align:center;border-left:4px solid #ffc107;}.tip-title{font-weight:600;color:#856404;margin-bottom:10px;}.tip-content{color:#856404;font-size:1rem;}.highlight{font-weight:bold;color:#000;background:#fff;padding:2px 6px;border-radius:4px;}@media (max-width:768px){.container{padding:20px;}}</style></head><body><div class="container"><div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo" width="96" height="96"></div><h1 class="title">Hello shodowsocks！</h1><div class="tip-content">访问 <span class="highlight">${baseUrl}/你的UUID</span> 进入订阅中心</div></div></div></body></html>`;
    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}
