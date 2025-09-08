

<div align="center">

# CF-Workers-VLESS

**中文** | [English](README_EN.md)

Telegram交流反馈群组: https://t.me/eooceu

基于 Cloudflare Workers 的高性能 VLESS 代理服务

</div>

## 功能特性

- 🚀 基于 Cloudflare Workers 的高性能代理
- 🔐 密码保护的主页访问
- 📱 支持多种客户端(v2rayN,shadowrocket,loon,karing,clash,sing-box等)
- 🌐 自动故障转移和负载均衡
- 📊 实时连接测试和状态监控

## 环境变量配置

### 必需变量

| 变量名 | 描述 | 默认值 | 示例 |
|--------|------|--------|------|
| `PASSWORD` | 主页访问密码 | `123456` | `your_web_password` |

### 可选变量

| 变量名 | 描述 | 默认值 | 示例 |
|--------|------|--------|------|
| `UUID`或`AUTH`或`uuid` | 用户UUID | `5dc15e15-f285-4a9d-959b-0e4fbdd77b63` | `your-uuid` |
| `PROXYIP`或`proxyip`或`proxyIP` | 代理服务器IP列表 | `13.230.34.30` | `tw.tp81.netlib.re` |
| `SUB_PATH`或`subpath` | 订阅路径 | `link` | `sub` |

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

## 许可证

GPL 2.0
