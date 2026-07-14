# go-pkg-httpauth

`pkg/httpauth` 为 Go HTTP 服务提供统一的浏览器 Session、Bearer 认证、登录方式发现、
授权中间件和认证路由。静态 token 与 OIDC 是可组合的认证驱动，应用只暴露一套
Session API。

## HTTP API

默认挂载路径为 `/auth`：

```text
GET    /auth/session
DELETE /auth/session
POST   /auth/login/token
GET    /auth/login/github
GET    /auth/callback/github
```

`GET /auth/session` 将当前认证状态与可用登录方式合并为一个响应：

```json
{
  "status": "authenticated",
  "method": "github",
  "access": "granted",
  "methods": [
    {"id": "token", "flow": "secret", "label": "Access token"},
    {"id": "github", "flow": "redirect", "label": "GitHub"}
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
	"github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth"
	"github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth/oidc"
	"github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth/oidc/dexgithub"
	"github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth/statictoken"
)

tokenMethod, err := statictoken.New("myapp", statictoken.Config{
	Credentials: map[string]statictoken.Credential{
		"admin": {Name: "Administrator", SecretSHA256: os.Getenv("API_ACCESS_TOKEN_SECRET_SHA256")},
	},
})
if err != nil {
	log.Fatal(err)
}

githubMethod, err := dexgithub.New(ctx, oidc.Config{
	ID:         "github",
	Label:      "GitHub",
	Issuer:     "https://dex.example.com",
	ClientID:   "tool",
	SessionTTL: 24 * time.Hour,
}, oidc.Options{})
if err != nil {
	log.Fatal(err)
}

githubUsers, err := dexgithub.NewUsernameAuthorizer([]string{"lwmacct"})
if err != nil {
	log.Fatal(err)
}

auth, err := httpauth.New(httpauth.Config{
	ExternalURLs: []string{"https://tool.example.com"},
	Session: httpauth.SessionConfig{
		TTL: 24 * time.Hour,
		Keys: []httpauth.SessionKey{
			{ID: "2026-07", Secret: os.Getenv("AUTH_SESSION_KEY")},
		},
	},
}, []httpauth.Method{tokenMethod, githubMethod}, httpauth.Options{
	Authorizer: githubUsers,
})
if err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/auth/", auth.Handler())
mux.Handle("/api/", auth.RequireAccess(api))
```

Session key 是 base64url 编码的 32 字节随机值，可使用以下命令生成：

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

`Session.Keys` 是 key ring。第一把 key 用于写入，所有 key 都可解密；轮换时先将新 key
插入首位，旧 Session 在旧 key 移除前继续有效。

静态 token 使用 `<namespace>.10.<credential-id>.<secret>` 格式。namespace 由应用定义，
secret 是 24 个随机字节的无填充 Base64URL 编码；配置只保存解码后 secret 的小写十六进制 SHA-256 摘要。
可用 `statictoken.Generate("myapp", "admin")` 同时生成 token 和配置摘要。旧式任意字符串、
UUID、错误版本、非规范 Base64URL 与带前后空白的 token 均不接受。

## 安全模型

- HTTPS 使用 `__Host-httpauth` Cookie；loopback HTTP 开发环境使用 `httpauth`。
- Session 使用 AES-256-GCM 加密认证，编码后最大 3800 字节。
- Session 不保存原始静态 token 或 OIDC ID Token。
- 静态 token Session 保存 credential ID 与 secret revision；删除或轮换 secret 会立即撤销。
- OIDC 使用 Authorization Code Flow、PKCE S256、nonce、单次 state 和可信 Host callback。
- OIDC Session 不会晚于 ID Token 或配置的 Session TTL 到期。
- Cookie Session 发起不安全 HTTP 方法时必须提供精确匹配的可信 `Origin`。
- `Authorization` 头存在时只尝试 Bearer；认证失败不会降级到 Cookie。

OIDC provider 必须注册由 method ID 派生的 callback，例如：

```text
https://tool.example.com/auth/callback/github
```

`oidc` 驱动要求 provider 支持 OpenID Connect discovery 并返回可验证的 ID Token。
`dexgithub` 适配的是 Dex GitHub connector 的 claims，不支持直接连接 GitHub OAuth App；
GitHub 原生 OAuth 需要单独的 OAuth 驱动，通过 GitHub API 获取并映射用户身份。

## 验证

```bash
go test ./...
go test -race ./...
go vet ./...
```
