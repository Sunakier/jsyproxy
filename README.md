# JSYProxy - 用于解决某机场的五分钟一次性订阅链接

一个用Go语言编写的HTTP代理服务器，提供特定接口的代理功能，支持Token鉴权和上游API调用。

## 快速开始

### 使用预构建镜像（推荐）

```bash
# 拉取并运行
docker run -d \
  --name jsyproxy \
  -p 3000:3000 \
  -e ADMIN_PASSWORD=change_me \
  ghcr.io/Sunakier/jsyproxy:latest
```

### 使用Docker Compose

```bash
# 设置环境变量
export ADMIN_PASSWORD=change_me

# 启动服务
docker-compose up -d
```

## 环境变量配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PORT` | 3000 | HTTP服务监听端口 |
| `ACCESS_KEYS` | 空 | 可选：启动时预置多Key（逗号分隔） |
| `ADMIN_PASSWORD` | 无 | 后台登录密码（必填） |
| `DEFAULT_REFRESH_INTERVAL` | 10m | 默认刷新周期（支持 `10m`/`5m`/`125s`） |
| `DATA_FILE` | data/state.json | Key和日志持久化文件 |
| 上游URL/请求头 | - | 全部改为管理台动态配置 |

## API使用

```bash
GET /apix/getSubscribe?token=<access_key>
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

1. 服务启动后立刻拉取订阅内容并建立缓存
2. 刷新周期由管理台配置（例如 `10m` / `5m` / `125s`）并动态生效
3. 客户端访问 `/apix/getSubscribe?token=xxxxx`
4. 服务器验证多Key并直接返回缓存内容（快速响应）
5. 记录客户端更新日志（IP、UA、命中缓存、结果）
6. 状态页同步显示流量/到期信息（已用上行+下行/总流量、到期时间、重置日、套餐名）

## 管理后台

- 页面：`GET /admin`
- 登录：`POST /admin/api/login`
- 主要API：
  - `GET /admin/api/status`
  - `GET /admin/api/settings`
  - `PUT /admin/api/settings`
  - `POST /admin/api/refresh`
  - `GET /admin/api/keys`
  - `POST /admin/api/keys`
  - `DELETE /admin/api/keys/:key`
  - `GET /admin/api/logs`

## 错误码

- **401**: Token缺失或无效
- **403**: 访问被拒绝的路径
- **502**: 上游服务不可用或响应错误

## 许可证

MIT License
