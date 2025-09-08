<div align="center">

# CF-Workers-VLESS

[中文](README.md) | **English**

Telegram Discussion & Feedback Group: https://t.me/eooceu

High-performance VLESS proxy service based on Cloudflare Workers

</div>

## Features

- 🚀 High-performance proxy based on Cloudflare Workers
- 🔐 Password-protected homepage access
- 📱 Support for multiple clients (v2rayN, shadowrocket, loon, karing, clash, sing-box, etc.)
- 🌐 Automatic failover and load balancing
- 📊 Real-time connection testing and status monitoring
- 🎨 Modern responsive interface

## Environment Variables

### Required Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `PASSWORD` | Homepage access password | `123456` | `your_web_password` |

### Optional Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `UUID` / `AUTH` / `uuid` | User UUID | `5dc15e15-f285-4a9d-959b-0e4fbdd77b63` | `your-uuid-here` |
| `PROXYIP` / `proxyip` / `proxyIP` | Proxy server IP list | `13.230.34.30` | `ip1,ip2,ip3` |
| `SUB_PATH` / `subpath` | Subscription path | `link` | `sub` |

## Deployment Steps

### Method 1: Via Cloudflare Dashboard

1. **Login to Cloudflare Dashboard**
   - Visit [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - Login to your account

2. **Create Worker**
   - Click "Workers & Pages"
   - Click "Create application"
   - Select "Create Worker"
   - Enter Worker name (avoid keywords like vless, proxy, etc., recommend using default)

3. **Upload Code**
   - Copy `_worker.js` file content to editor
   - Click "Deploy" in the top right corner

4. **Configure Environment Variables**
   - Find "Settings" → "Variables" in Worker settings
   - Add required environment variables and bind custom domain
   - Click "Save"

5. **Access Custom Domain**
   - Enter login password to access homepage and view subscription links

## License

GPL 2.0
