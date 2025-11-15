

<div align="center">

# Workers & Snippets deploy VLESS + trojan + shadowsocks

**中文** | [English](README_EN.md)

Telegram交流反馈群组: https://t.me/eooceu

基于 Cloudflare Workers & Snippets 的高性能 VLESS+trojan 代理服务

YouTube视频部署教程：https://youtu.be/GEcKz2NoKlM

Shadowsocks部署视频教程：https://youtu.be/hUPN_69Atow

</div>

## 功能特性

- 🚀 基于 Cloudflare Workers 和 snippets 的高性能代理
- 🌐 vless + trojan 双协议支持
- 🔐 密码保护的主页访问
- 📱 支持多种客户端(v2rayN,shadowrocket,loon,karing,clash,sing-box等)
- 🌐 自动故障转移和负载均衡
- 📊 实时连接测试和状态监控
- 📊 默认禁用speedtest测速

## 环境变量配置

### 必需变量

| 变量名 | 描述 | 默认值 | 示例 |
|--------|------|--------|------|
| `PASSWORD` | 主页访问密码 | `123456` | `your_web_password` |

### workers可选变量

| 变量名 | 描述 | 默认值 | 示例 |
|--------|------|--------|------|
| `UUID`或`AUTH`或`uuid` | 用户UUID | `5dc15e15-f285-4a9d-959b-0e4fbdd77b63` | `your-uuid` |
| `PROXYIP`或`proxyip`或`proxyIP` | 代理服务器IP列表 | `13.230.34.30` | `tw.tp81.netlib.re` |
| `SUB_PATH`或`subpath` | 订阅路径 | `link` | `sub` |
| `DISABLE_TROJAN`或`CLOSE_TROJAN` | 是否关闭Trojan协议，true关闭，false开启 | `false` | 默认开启 |

## 部署步骤

1. **登录 Cloudflare Dashboard**
   - 访问 [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - 登录你的账户

2. **创建 Worker**
   - 点击 "Workers & Pages"
   - 点击 "Create application"
   - 选择 "Create Worker"
   - 输入 Worker 名称(不要带vless,proxy之类的关键词，建议默认)

3. **上传代码**
   - 将 `_worker.js` 文件内容复制到编辑器
   - 点击 右上角 "Deploy"

4. **配置环境变量**
   - 在 Worker 设置中找到 "Settings" → "Variables"
   - 添加所需的环境变量并绑定自定义域名
   - 点击 "Save"

5. **访问自定义域名**
   - 输入登录密码进入主页查看相关订阅链接

## snippets / workers 路径进阶用法

### 相关路径说明
<img width="700" height="600" alt="image" src="https://github.com/user-attachments/assets/86b3dd1d-bbca-4786-9bb3-430bf6700024" />

| 类型 | 示例 | 说明 |
|------|------|------|
| **默认路径** | `/?ed=2560` | 使用代码里设置的默认 `proxyip` |
| **域名 proxyip** | `/?ed=2560&proxyip=proxyip.domain.com` 或 `proxyip=proxyip.domain.com`  | 使用域名形式的 `proxyip` |
| **带端口的 proxyip** | `/?ed=2560&proxyip=ip:port` 或 `/proxyip=ip:port` | 使用带端口的 `proxyip` |
| **SOCKS5** | `/?ed=2560&proxyip=socks://user:pass@host:port` 或 `/proxyip=socks://user:pass@host:port` | 使用全局 SOCKS5 出站 协议头可为socks5 |
| **HTTP** | `/?ed=2560&proxyip=http://user:pass@host:port` 或 `/proxyip=http://user:pass@host:port` | 使用全局 HTTP/HTTPS 出站 |


## cloudns 双向解析域名部署snippets统一使用的域名前缀
```bash
_acme-challenge
```

## shadowsocks 节点参数对照图
<img width="1540" height="1293" alt="image" src="https://github.com/user-attachments/assets/7a7b684e-f58f-4f09-a4a9-ca54d7a21d2f" />


## 许可证

GPL 2.0
