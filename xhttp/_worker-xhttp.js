// 温馨提示：绑定自定义域名后，需要在域名下左侧的网络菜单开启GRPC功能，否则不通

import { connect } from 'cloudflare:sockets'

let yourUUID = '5dc15e15-f285-4a9d-959b-0e4fbdd77b63';  // UUID
let proxyIP = 'ProxyIP.SG.CMLiussss.net';  // proxyIP  感谢CM大佬维护的proxyip
let subPath = 'link';  // 订阅token,建议修改,默认不变将使用UUID作为订阅路径

let cfip = [ // cfip
    'ip.sb', 'time.is', 'skk.moe', 'www.visa.com.tw', 'www.visa.com.hk', 'www.visa.com.sg',
    'cf.090227.xyz','cf.877774.xyz', 'cdns.doon.eu.org', 'cf.zhetengsha.eu.org'
];

let ACTIVE_CONNECTIONS = 0
const BUFFER_SIZE = 128 * 1024
const CONNECT_TIMEOUT_MS = 5000  
const IDLE_TIMEOUT_MS = 45000    
const MAX_RETRIES = 2           
const MAX_CONCURRENT = 32       

function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms))
}

function validate_uuid(id, uuid) {
    for (let index = 0; index < 16; index++) {
        const v = id[index]
        const u = uuid[index]
        if (v !== u) {
            return false
        }
    }
    return true
}

class Counter {
    #total

    constructor() {
        this.#total = 0
    }

    get() {
        return this.#total
    }

    add(size) {
        this.#total += size
    }
}

function concat_typed_arrays(first, ...args) {
    let len = first.length
    for (let a of args) {
        len += a.length
    }
    const r = new first.constructor(len)
    r.set(first, 0)
    len = first.length
    for (let a of args) {
        r.set(a, len)
        len += a.length
    }
    return r
}

function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '')
    const r = []
    for (let index = 0; index < 16; index++) {
        const v = parseInt(uuid.substr(index * 2, 2), 16)
        r.push(v)
    }
    return r
}

function get_buffer(size) {
    return new Uint8Array(new ArrayBuffer(size || BUFFER_SIZE))
}

// enums
const ADDRESS_TYPE_IPV4 = 1
const ADDRESS_TYPE_URL = 2
const ADDRESS_TYPE_IPV6 = 3

async function read_header(readable, uuid_str) {
    const reader = readable.getReader({ mode: 'byob' })

    try {
    let r = await reader.readAtLeast(1 + 16 + 1, get_buffer())
    let rlen = 0
    let idx = 0
    let cache = r.value
    rlen += r.value.length

    const version = cache[0]
    const id = cache.slice(1, 1 + 16)
    const uuid = parse_uuid(uuid_str)
    if (!validate_uuid(id, uuid)) {
        return `invalid UUID`
    }
    const pb_len = cache[1 + 16]
    const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1

    if (addr_plus1 + 1 > rlen) {
        if (r.done) {
            return `header too short`
        }
        idx = addr_plus1 + 1 - rlen
        r = await reader.readAtLeast(idx, get_buffer())
        rlen += r.value.length
        cache = concat_typed_arrays(cache, r.value)
    }

    const cmd = cache[1 + 16 + 1 + pb_len]
    if (cmd !== 1) {
        return `unsupported command: ${cmd}`
    }
    const port = (cache[addr_plus1 - 1 - 2] << 8) + cache[addr_plus1 - 1 - 1]
    const atype = cache[addr_plus1 - 1]
    let header_len = -1
    if (atype === ADDRESS_TYPE_IPV4) {
        header_len = addr_plus1 + 4
    } else if (atype === ADDRESS_TYPE_IPV6) {
        header_len = addr_plus1 + 16
    } else if (atype === ADDRESS_TYPE_URL) {
        header_len = addr_plus1 + 1 + cache[addr_plus1]
    }

    if (header_len < 0) {
        return 'read address type failed'
    }

    idx = header_len - rlen
    if (idx > 0) {
        if (r.done) {
            return `read address failed`
        }
        r = await reader.readAtLeast(idx, get_buffer())
        rlen += r.value.length
        cache = concat_typed_arrays(cache, r.value)
    }

    let hostname = ''
    idx = addr_plus1
    switch (atype) {
        case ADDRESS_TYPE_IPV4:
            hostname = cache.slice(idx, idx + 4).join('.')
            break
        case ADDRESS_TYPE_URL:
            hostname = new TextDecoder().decode(
                cache.slice(idx + 1, idx + 1 + cache[idx]),
            )
            break
        case ADDRESS_TYPE_IPV6:
            hostname = cache
                .slice(idx, idx + 16)
                .reduce(
                    (s, b2, i2, a) =>
                        i2 % 2
                            ? s.concat(((a[i2 - 1] << 8) + b2).toString(16))
                            : s,
                    [],
                )
                .join(':')
            break
    }

    if (hostname.length < 1) {
        return 'failed to parse hostname'
    }

    const data = cache.slice(header_len)
    return {
        hostname,
        port,
        data,
        resp: new Uint8Array([version, 0]),
        reader,
        done: r.done,
        }
    } catch (error) {
        try { reader.releaseLock() } catch (_) {}
        throw error
    }
}

async function upload_to_remote(counter, writer, httpx) {
    async function inner_upload(d) {
        if (!d || d.length === 0) {
            return
        }
        counter.add(d.length)
        try {
        await writer.write(d)
        } catch (error) {
            throw error
        }
    }

    try {
        await inner_upload(httpx.data)
        let chunkCount = 0
        while (!httpx.done) {
            const r = await httpx.reader.read(get_buffer())
            if (r.done) break
            await inner_upload(r.value)
            httpx.done = r.done
            chunkCount++
            if (chunkCount % 10 === 0) {
                await sleep(0)
            }
            if (!r.value || r.value.length === 0) {
                await sleep(2)
            }
        }
    } catch (error) {
        throw error
    }
}

function create_uploader(httpx, writable) {
    const counter = new Counter()
        const writer = writable.getWriter()
    
    const done = (async () => {
        try {
            await upload_to_remote(counter, writer, httpx)
        } catch (error) {
            throw error
        } finally {
            try {
                await writer.close()
            } catch (error) {
                // ignore close errors
            }
        }
    })()

    return {
        counter,
        done,
        abort: () => {
            try { writer.abort() } catch (_) {}
        }
    }
}

function create_downloader(resp, remote_readable) {
    const counter = new Counter()
    let stream

    const done = new Promise((resolve, reject) => {
        stream = new TransformStream(
            {
                start(controller) {
                    counter.add(resp.length)
                    controller.enqueue(resp)
                },
                transform(chunk, controller) {
                    counter.add(chunk.length)
                    controller.enqueue(chunk)
                },
                cancel(reason) {
                    reject(`download cancelled: ${reason}`)
                },
            },
            null,
            new ByteLengthQueuingStrategy({ highWaterMark: BUFFER_SIZE }),
        )

        let lastActivity = Date.now()
        const idleTimer = setInterval(() => {
            if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
                try {
                    stream.writable.abort?.('idle timeout')
                } catch (_) {}
                clearInterval(idleTimer)
                reject('idle timeout')
            }
        }, 5000)

        const reader = remote_readable.getReader()
        const writer = stream.writable.getWriter()

        ;(async () => {
            try {
                let chunkCount = 0
                while (true) {
                    const r = await reader.read()
                    if (r.done) {
                        break
                    }
                    lastActivity = Date.now()
                    await writer.write(r.value)
                    chunkCount++
                    // 每处理5个chunk就yield一次CPU
                    if (chunkCount % 5 === 0) {
                        await sleep(0)
                    }
                }
                await writer.close()
                resolve()
            } catch (err) {
                reject(err)
            } finally {
                try { 
                    reader.releaseLock() 
                } catch (_) {}
                try { 
                    writer.releaseLock() 
                } catch (_) {}
                clearInterval(idleTimer)
            }
        })()
    })

    return {
        readable: stream.readable,
        counter,
        done,
        abort: () => {
            try { stream.readable.cancel() } catch (_) {}
            try { stream.writable.abort() } catch (_) {}
        }
    }
}

async function connect_to_remote(httpx, ...remotes) {
    let attempt = 0
    let lastErr
    
    const connectionList = [httpx.hostname, ...remotes.filter(r => r && r !== httpx.hostname)]
    
    for (const hostname of connectionList) {
        if (!hostname) continue
        
        attempt = 0
        while (attempt < MAX_RETRIES) {
            attempt++
            try {
                const remote = connect({ hostname, port: httpx.port })
                const timeoutPromise = sleep(CONNECT_TIMEOUT_MS).then(() => {
                    throw new Error('connect timeout')
                })
                
                await Promise.race([remote.opened, timeoutPromise])

                const uploader = create_uploader(httpx, remote.writable)
                const downloader = create_downloader(httpx.resp, remote.readable)
                
                return { 
                    downloader, 
                    uploader,
                    close: () => {
                        try { remote.close() } catch (_) {}
                    }
                }
            } catch (err) {
                lastErr = err
                if (attempt < MAX_RETRIES) {
                    await sleep(500 * attempt) 
                }
            }
        }
    }
    
    return null
}

async function handle_client(body, cfg) {
    if (ACTIVE_CONNECTIONS >= MAX_CONCURRENT) {
        return new Response('Too many connections', { status: 429 })
    }
    
    ACTIVE_CONNECTIONS++
    
    let cleaned = false
    const cleanup = () => {
        if (!cleaned) {
            ACTIVE_CONNECTIONS = Math.max(0, ACTIVE_CONNECTIONS - 1)
            cleaned = true
        }
    }

    try {
    const httpx = await read_header(body, cfg.UUID)
    if (typeof httpx !== 'object' || !httpx) {
        return null
    }

        // 尝试连接：直连 -> 主proxyIP -> 兜底proxyIP 13.230.34.30
        const remoteConnection = await connect_to_remote(httpx, cfg.PROXYIP, '13.230.34.30')  
        if (remoteConnection === null) {
            return null
        }

        const connectionClosed = Promise.race([
            (async () => {
                try {
                    await remoteConnection.downloader.done
                } catch (err) {
                    // ignore download errors
                }
            })(),
            (async () => {
                try {
                    await remoteConnection.uploader.done
                } catch (err) {
                    // ignore upload errors
                }
            })(),
            sleep(IDLE_TIMEOUT_MS).then(() => {
                // global timeout
            })
        ]).finally(() => {
            try { remoteConnection.close() } catch (_) {}
            try { remoteConnection.downloader.abort() } catch (_) {}
            try { remoteConnection.uploader.abort() } catch (_) {}
            
            cleanup()
    })

    return {
            readable: remoteConnection.downloader.readable,
            closed: connectionClosed
        }
    } catch (error) {
        cleanup()
        return null
    }
}

async function handle_post(request, cfg) {
    try {
        return await handle_client(request.body, cfg)
    } catch (err) {
    return null
    }
}

function generate_link(uuid, hostname, port, path, sni, currentHost) {
    const protc = 'x' + 'h' + 't' + 't' + 'p'
    const header = 'v' + 'l' + 'e' + 's' + 's'

    const params = new URLSearchParams({
        encryption: 'none',
        security: 'tls',
        sni: sni || currentHost,
        fp: 'chrome',
        allowInsecure: '1',
        type: protc,
        host: currentHost, 
        path: path.startsWith('/') ? path : `/${path}`,
        mode: 'stream-one'
    })

    return `${header}://${uuid}@${hostname}:${port}?${params.toString()}#Workers-${header}-${protc}`
}

function generate_subscription(uuid, cfipList, port = 443, path, sni, currentHost) {
    const links = cfipList.map(hostname => 
        generate_link(uuid, hostname, port, path, sni, currentHost)
    )
    
    return btoa(links.join('\n'))
}

async function fetch(request, env, ctx) {
    const cfg = {
        UUID: env.UUID || env.uuid || env.AUTH || yourUUID,
        PROXYIP: env.PROXYIP || env.proxyip || proxyIP,
        SUB_PATH: env.SUB_PATH || env.subpath || subPath,
    }

    if (!cfg.UUID) {
        return new Response(`Error: UUID is empty`, { status: 400 })
    }

    const url = new URL(request.url)

    if (request.method === 'POST') {
        const r = await handle_post(request, cfg)
        if (r) {
            ctx.waitUntil(r.closed)
            return new Response(r.readable, {
                headers: {
                    'X-Accel-Buffering': 'no',
                    'Cache-Control': 'no-store',
                    Connection: 'keep-alive',
                    'User-Agent': 'Go-http-client/2.0',
                    'Content-Type': 'application/grpc',
                },
            })
        }
        return new Response('Internal Server Error', { status: 500 })
    }

    if (request.method === 'GET') {
        const path = url.pathname
        
        if (path.includes(cfg.UUID) || path.includes(cfg.SUB_PATH)) {
            const port = 443
            const nodePath = cfg.UUID.substring(0, 8)
            const sni = url.searchParams.get('sni') || url.hostname
            const currentHost = url.hostname
            
            const subscription = generate_subscription(
                cfg.UUID,
                cfip,
                port,
                nodePath,
                sni,
                currentHost
            )
            
            return new Response(subscription, {
                    headers: {
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
            })
        }
        
    return new Response(`Hello world!`)
}

    return new Response('Method Not Allowed', { status: 405 })
}

export default { fetch }
