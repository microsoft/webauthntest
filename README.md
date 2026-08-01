## Live instance
A live instance of this code is available at [aka.ms/ctap](https://aka.ms/ctap) or [ctap.dev](https://ctap.dev). This instance is for testing the WebAuthn API only. Do not submit personal data.

This project is a client-only WebAuthn playground. Cloudflare Workers Static Assets serves the files in `public/`, while challenges, credential parsing, assertion verification, and credential storage all run in the browser.

Credential details are stored in IndexedDB for the current browser profile and origin. The selected username is stored in localStorage, and pending one-time challenges are kept in sessionStorage. Nothing is written to a server-side database.

## Deploying to Cloudflare

The Cloudflare Worker application is named `passkey`. It is an assets-only Worker: it has no Worker script, D1 binding, secrets, or runtime environment variables.

### Install and build

```powershell
npm install
npm run build
```

The build bundles the browser-side WebAuthn verification and IndexedDB adapter into `public/client-backend.js`.

### Local development

```powershell
npm run dev:worker
```

### Deploy

Authenticate once, then deploy:

```powershell
npx wrangler login
npm run deploy:worker
```

Wrangler creates or updates the separate `passkey` Worker application.

To attach a hostname, add it in **Workers & Pages → passkey → Settings → Domains & Routes → Add Custom Domain**, or add this to `wrangler.toml`:

```toml
[[routes]]
pattern = "passkeys.example.com"
custom_domain = true
```

Changing the hostname changes the WebAuthn relying-party scope. Credentials registered on another hostname generally cannot be used on the new hostname.

## Client-only limitations

- Stored credential details do not synchronize across browsers or devices.
- Clearing site data removes the local credential records displayed by the playground.
- Client-side verification is intended for testing and education, not as a trusted authentication backend.
- The UI currently loads some libraries, fonts, and authenticator metadata from external CDNs and GitHub.

## Contributing
This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

## Code of Conduct
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
