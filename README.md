# go-pkg-authme

`pkg/authme` 为 Go HTTP 服务提供统一的浏览器 Session、Bearer 认证、登录方式发现、
授权中间件和认证路由。静态 token 与 OIDC 是可组合的认证驱动，应用只暴露一套
Session API。每个认证 adapter 的 `enabled` 字段由调用方决定是否启用；未启用的 adapter 不会初始化或校验。

## HTTP API

默认挂载路径为 `/authme`：

```text
GET    /authme/session
DELETE /authme/session
POST   /authme/login/token
GET    /authme/login/github
GET    /authme/callback/github
```

`GET /authme/session` 将当前认证状态与可用登录方式合并为一个响应：

```json
{
  "status": "authenticated",
  "method": "github",
  "access": "granted",
  "methods": [
    { "id": "token", "flow": "secret", "label": "Access token" },
    { "id": "github", "flow": "redirect", "label": "GitHub" }
  ],
  "identity": {
    "subject": "dex-subject",
    "username": "lwmacct",
    "provider": "github"
  }
}
```

未登录返回 `200` 与 `{"status":"signed-out", ...}`。显式 Bearer 无效时返回 `401`，
不会降级使用浏览器 Session。

错误使用稳定 code：

```json
{
  "error": {
    "code": "authentication_required",
    "message": "Authentication required"
  }
}
```

## 使用

```go
import (
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/adapters/dexgithub"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/adapters/statictoken"
)

tokenMethod, err := statictoken.New(statictoken.Config{
	Enabled: true,
	Credentials: []statictoken.Credential{
		{ID: "admin", Name: "Administrator", Token: os.Getenv("AUTHME_ACCESS_TOKEN")},
	},
})
if err != nil {
	log.Fatal(err)
}

githubMethod, err := dexgithub.New(ctx, dexgithub.Config{
	Enabled: true,
	ID:         "github",
	Label:      "GitHub",
	Issuer:     "https://dex.example.com",
	ClientID:   "tool",
	SessionTTL: 24 * time.Hour,
})
if err != nil {
	log.Fatal(err)
}

githubUsers, err := dexgithub.NewUsernameAuthorizer([]string{"lwmacct"})
if err != nil {
	log.Fatal(err)
}

auth, err := authme.New(authme.Config{
	Origins: []string{"https://tool.example.com"},
	Session: authme.SessionConfig{
		TTL: 24 * time.Hour,
		Keys: []authme.SessionKey{
			{ID: "2026-07", Secret: os.Getenv("AUTHME_SESSION_KEY")},
		},
	},
}, authme.WithMethods(tokenMethod, githubMethod), authme.WithAuthorizer(githubUsers))
if err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle(auth.PathPrefix()+"/", auth.Handler())
mux.Handle("/api/", auth.RequireAccess(api))
```

Session key 是 base64url 编码的 32 字节随机值，可使用以下命令生成：

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

`Session.Keys` 是 key ring。第一把 key 用于写入，所有 key 都可解密；轮换时先将新 key
插入首位，旧 Session 在旧 key 移除前继续有效。

`origins` 支持配置多个域名，但同一个 AuthMe 实例中的 origin 必须统一使用 HTTP 或
HTTPS。Cookie 的 `Secure`、OIDC flow cookie 和 CSRF Origin 校验是实例级策略；开发环境
可使用 loopback HTTP，生产环境应使用 HTTPS。若需要同时访问本地和生产地址，建议为本地
开发也配置 HTTPS，而不是混用两种协议。

静态 token 是 opaque Bearer secret，不规定 namespace、版本、credential ID 或编码格式。
只要是非空且不含空白/控制字符的字符串即可；配置直接保存 token，适合沿用 Redis ACL、
上游 API key 或现有密钥。服务启动时只计算 SHA-256 verifier，运行时不保存明文 token。
生产环境应使用密码管理器或环境变量注入高熵随机值；短或可猜的 token 仍然不安全。

## 安全模型

- HTTPS 使用 `__Host-authme` Cookie；loopback HTTP 开发环境使用 `authme`。
- Session 使用 AES-256-GCM 加密认证，编码后最大 3800 字节。
- Session 不保存原始静态 token 或 OIDC ID Token。
- 静态 token Session 保存 credential ID 与 secret revision；删除或轮换 secret 会立即撤销。
- OIDC 使用 Authorization Code Flow、PKCE S256、nonce、单次 state 和可信 Host callback。
- OIDC Session 不会晚于 ID Token 或配置的 Session TTL 到期。
- Cookie Session 发起不安全 HTTP 方法时必须提供精确匹配的可信 `Origin`。
- `Authorization` 头存在时只尝试 Bearer；认证失败不会降级到 Cookie。

OIDC provider 必须注册由 method ID 派生的 callback，例如：

```text
https://tool.example.com/authme/callback/github
```

`pkg/oidc` 是不依赖 `authme` 的协议包，负责 discovery、PKCE、nonce、code exchange
和 ID Token 验证。`dexgithub` 适配 Dex GitHub connector 的 claims。

## 验证

```bash
go test ./...
go test -race ./...
go vet ./...
```
