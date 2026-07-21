## Live instance
A live instance of this code is available at [aka.ms/ctap](https://aka.ms/ctap) or [ctap.dev](https://ctap.dev). This instance is for testing the WebAuthn API only. Do not submit personal data.

This project is an edge-native Cloudflare Worker that serves the static UI from `public/` (Workers Assets) and exposes the API endpoints, backed by a D1 (SQLite) database.

## Deploying to Cloudflare (edge-native)

This repo can be deployed as a Cloudflare Worker that serves the static UI from `public/` (Workers Assets) and exposes the API endpoints.

### 1) Create a D1 database
- Create a D1 database named `webauthntest`
- Apply schema locally: `npm run db:apply`
- Apply schema to Cloudflare: `npm run db:apply:remote`
- Put the D1 `database_id` into `wrangler.toml`

### 2) Configure environment variables (Worker settings)
- `CHALLENGE_HMAC_SECRET` (required): long random secret used to sign one-time WebAuthn challenges
- `UID_HASH_SECRET` (optional): if set, usernames are hashed using HMAC-SHA256 instead of plain SHA-256
- `HOSTNAME` / `CUSTOM_DOMAIN` (optional): allowlisted hostname(s) for origin checks (the request hostname is always allowed)
- `APP_VERSION` (optional): shown at `/metadata`

### 3) Local dev
- `npm install`
- `npm run dev:worker`

### One-command deploy

Prereqs (one-time per Cloudflare account/project):
- Authenticate: `npx wrangler login`
- Set `database_id` in `wrangler.toml`
- Set required secret on the Worker: `npx wrangler secret put CHALLENGE_HMAC_SECRET --name webauthntest`

Then deploy with a single command:
- `npm run deploy:worker`

### Fresh clone: one command

From a fresh clone (no `node_modules/`), this single command will:
- install dependencies
- prompt you to log into Cloudflare (first time only)
- create the D1 database (if needed)
- apply the D1 schema
- set `CHALLENGE_HMAC_SECRET`
- deploy

Run:
- `npm run bootstrap:cf`

Optional environment variables:
- `CF_WORKER_NAME` (default: `webauthntest`)
- `CF_D1_NAME` (default: `webauthntest`)
- `CHALLENGE_HMAC_SECRET` (if set, uses your value instead of generating one)

Notes:
- The edge-native version uses D1 instead of MongoDB.

## Contributing
This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

## Code of Conduct
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

