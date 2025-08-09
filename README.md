# JSYProxy - 用于解决某机场的五分钟一次性订阅链接

一个用Go语言编写的HTTP代理服务器，提供特定接口的代理功能，支持Token鉴权和上游API调用。

## 快速开始

### 使用预构建镜像（推荐）

```bash
# 拉取并运行
docker run -d \
  --name jsyproxy \
  -p 3000:3000 \
  -e AUTHORIZATION=your_token_here \
  ghcr.io/Sunakier/jsyproxy:latest
```

### 使用Docker Compose

```bash
# 设置环境变量
export AUTHORIZATION=your_authorization_token_here

# 启动服务
docker-compose up -d
```

## 环境变量配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PORT` | 3000 | HTTP服务监听端口 |
| `TOKEN` | PKenOMF2rAwf1df | 鉴权Token |
| `UPSTREAM_URL` | https://api.ajin168.com/api/v1/user/getSubscribe | 上游API地址 |
| `AUTHORIZATION` | 无 | 上游API授权头（必需） |
| `USER_AGENT` | Mozilla/5.0... | 请求User-Agent |
| `HOST` | api.ajin168.com | 请求Host头 |
| `ORIGIN` | https://w4.rouhe88.com | 请求Origin头 |
| `REFERER` | https://w4.rouhe88.com/ | 请求Referer头 |

## API使用

```bash
GET /apix/getSubscribe?token=PKenOMF2rAwf1df
```

**示例：**
```bash
curl "http://localhost:3000/apix/getSubscribe?token=PKenOMF2rAwf1df"
```

## 本地开发

```bash
# 安装依赖
go mod download

# 运行程序
go run main.go
```

**要求：** Go 1.21+

## 工作流程

1. 客户端访问 `/apix/getSubscribe?token=xxxxx`
2. 服务器验证Token参数
3. 调用上游API获取JSON响应
4. 解析 `subscribe_url` 字段
5. 使用客户端User-Agent请求 `subscribe_url` 获取内容
6. 透传响应头和内容给客户端

## 错误码

- **401**: Token缺失或无效
- **403**: 访问被拒绝的路径
- **502**: 上游服务不可用或响应错误

## 许可证

MIT License