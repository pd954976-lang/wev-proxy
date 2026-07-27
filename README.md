# Private Web Relay — GitHub + Vercel

This repository deploys an authenticated HTTP/HTTPS API relay as Vercel Functions. It is intentionally restrictive and is **not** a SOCKS proxy, VPN, `CONNECT` tunnel, or IP-rotation system.

## Fastest setup

1. Extract this ZIP.
2. Double-click `PUSH_TO_GITHUB.cmd` to create and push one GitHub repository.
3. Open Vercel and choose **Add New → Project**.
4. Import the GitHub repository.
5. Leave Framework Preset as **Other** and deploy.
6. In **Project → Settings → Environment Variables**, add:

```text
RELAY_API_KEY=<your generated secret>
ALLOWED_HOSTS=example.com,api.example.com
ALLOW_ANY_PUBLIC_HOST=false
```

Run `GENERATE_SECRET.cmd` to create the secret. It is your own relay password; it is not an API key you must buy from another company.

After saving environment variables, redeploy from **Deployments → Redeploy**.

## Safe configuration

Use an explicit `ALLOWED_HOSTS` list. Wildcard subdomains are supported, for example:

```text
ALLOWED_HOSTS=api.github.com,*.example.org
```

`ALLOW_ANY_PUBLIC_HOST=true` permits any public host on ports 80/443. It remains authenticated and blocks private/local addresses, but it greatly increases abuse and bandwidth risk. Keep it false unless necessary.

## Endpoints

- `/` — browser dashboard
- `/api/health` — configuration/health status
- `/api/relay` — authenticated relay endpoint

Example:

```bash
curl -i https://YOUR-PROJECT.vercel.app/api/relay \
  -H "Content-Type: application/json" \
  -H "X-Relay-Key: YOUR_SECRET" \
  --data '{"url":"https://example.com/","method":"GET"}'
```

## Security controls

- Required secret with timing-safe comparison
- Explicit hostname allowlist by default
- DNS resolution and connection pinning
- Blocks loopback, private, link-local, documentation, multicast, and reserved address ranges
- Revalidates every redirect
- Allows only HTTP/HTTPS and target ports 80/443
- Request and response size caps
- Timeout and redirect limits
- Header allowlists
- Per-instance burst rate limiting

The in-memory rate limiter is only a best-effort serverless safeguard because Vercel can run multiple isolated function instances. Use Vercel's platform controls for stronger global abuse protection.

## Vercel limitations

Vercel exposes HTTPS Functions rather than arbitrary TCP ports. Therefore this project cannot run Squid/Dante, SOCKS5, browser-wide proxy settings, or HTTP `CONNECT`. Function request and response payloads are limited, and Hobby function duration is limited, so this is for modest API-style requests rather than large downloads or streaming.

## Local checks

```powershell
npm test
npm run check
```

For local Vercel emulation, install the CLI and run:

```powershell
npm i -g vercel
vercel dev
```

Keep `.env` and secrets out of GitHub.
