# BFFlash

A standalone Backend-for-Frontend. One binary, one YAML file, no code.

Put it in front of your frontend and APIs, and tokens leave the browser for good. The browser holds only an opaque session cookie, while BFFlash handles OIDC login, token refresh and forwarding.

## Declare services, not endpoints

You tell BFFlash where a service lives. You never list its routes.

```yaml
oidc:
  issuer: https://idp.example.com
  client_id: bfflash
  client_secret: ${OIDC_CLIENT_SECRET}

frontend:
  url: http://web:3000

apis:
  - path: /api
    to: http://gateway:8080
```

That is a complete config. Every path under `/api` requires a logged-in user and the CSRF header, and gets the user's access token forwarded. Adding a backend endpoint changes nothing here.

- **Prefixes are the unit of config.** Longest prefix wins, on segment boundaries, so `/api/orders` never matches `/api/ordersfoo`.
- **Secure by default.** Loosening a path is the explicit choice.
- **Defaults cascade.** Built-in, then `defaults:`, then the API, then a `rules:` entry.
- **Exceptions are optional.** `rules:` exist only for paths that differ.

`bfflash routes` prints what every path ends up with. [examples/full.yaml](examples/full.yaml) shows every setting.

## Run it

```bash
go build -o bfflash ./cmd/bfflash
```

```bash
./bfflash validate -c bfflash.yaml
```

```bash
./bfflash serve -c bfflash.yaml
```

`${VAR}` values come from the environment. Saving the file reloads it with no dropped requests, and a config that fails validation is logged and ignored while the old one keeps serving. Changing `session.store`, `session.url`, `session.encryption_key` or `server.listen` needs a restart.

Register `<public url>/bff/callback` as a redirect URI at your identity provider, and `<public url>/bff/backchannel-logout` as the back-channel logout URI.

## Frontend integration

Send `X-CSRF: 1` on every API call. Any value works: a custom header forces a CORS preflight on cross-origin calls, which is the protection. Missing it returns 401, including on GET.

| Endpoint | Use |
|---|---|
| `GET /bff/login?returnUrl=/path` | Navigate here to log in |
| `GET /bff/user` | Current user, or 401. Needs `X-CSRF` |
| `POST /bff/logout` | Needs `X-CSRF`. Clears the session and returns `{"redirect": url}` to navigate to |
| `GET <logout_url>` | The link from `/bff/user`, for a plain anchor |
| `POST /bff/backchannel-logout` | Called by the identity provider |
| `GET /healthz`, `/readyz` | Liveness, and readiness (provider and session store reachable) |

API calls without a session get a 401, never a redirect, so the frontend decides when to send the user to `/bff/login`.

WebSockets work, but browsers can't set headers on them, so an upgrade must carry an `Origin` matching the public URL instead.

## Token modes

| `token:` | Sent upstream | No session |
|---|---|---|
| `user` (default) | User access token, refreshed automatically | 401 |
| `client` | Client credentials token | Works |
| `user_or_client` | User token, else client token | Works |
| `user_or_none` | User token, else nothing | Works |
| `none` | Nothing | Works |

## Service templates

```yaml
- path: /api/{service}
  to: http://{service}.prod.svc:8080
  allow: [billing, search, users]
```

`allow` is mandatory. Without it, a crafted path could send a user's token to any host on the internal network.

## Aggregation

A composed endpoint is the one thing you do declare, because it doesn't exist on any backend.

```yaml
compose:
  - path: /api/dashboard
    steps:
      - { id: me, get: "/api/users/me" }
      - { id: orders, get: "/api/orders?user=${steps.me.body.id}", optional: true }
    respond: |
      {"name": steps.me.body.name, "orders": steps.orders.body}
```

- Steps go through the declared APIs, so they inherit token, timeout and rate rules.
- References set the order. Unrelated steps run in parallel.
- Each step exposes `.ok`, `.status` and `.body`. A failed `optional` step has `ok: false` and a null body.
- A failed required step returns 502, or the step's own status for 401 and 403, so the frontend can react.
- `${...}` and `respond` are [CEL](https://cel.dev) expressions, checked by `validate`. Values placed in URLs are escaped.

## Security

- Tokens stay on the server, encrypted with AES-256-GCM. Session store keys are hashes of the cookie value.
- Cookie: `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`. The ID rotates at login.
- OIDC uses `state`, `nonce` and PKCE. `returnUrl` accepts same-origin paths only.
- The browser's `Cookie` and `Authorization` headers never reach an upstream.
- Traversal in any encoding is rejected before routing, including double encoding.
- Cached responses are keyed by user unless the route is `token: none`. `Set-Cookie`, `private` and `no-store` responses are never stored.
- Retries apply to idempotent requests without a body.

## Limits

- **Default scopes include `offline_access`.** Some providers, Google among them, reject it. Set `oidc.scopes` for those.
- **HTTP only.** Terminate TLS in front of BFFlash. `__Host-` cookies need HTTPS, except on `localhost` in most browsers.
- **`memory` sessions die with the process** and can't be shared between replicas. Use `redis` for production.
- **Rate limits and the cache are per instance**, so N replicas allow N times the configured rate.
- **`per ip` uses the connection's address.** Behind a load balancer, every client shares one bucket.
- **Cached routes buffer the whole response**, and only responses up to 1 MiB are stored. Don't cache large downloads.
- **Back-channel logout removes the server session.** A cached response stays until its TTL ends, though only that user can receive it.

## Credits

The security model follows the BFF pattern as described by [Duende BFF](https://docs.duendesoftware.com/bff/), which is a .NET library. BFFlash shares no code with it.
