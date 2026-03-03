# X OAuth Worker for Website Time Tracker

This Cloudflare Worker handles X (Twitter) OAuth 2.0 authentication for the browser extension, keeping the client credentials secure on the server.

## Setup

### 1. Create X App

1. Go to https://developer.x.com and create a new app
2. Enable OAuth 2.0 in "User authentication settings"
3. Set App type to "Web App" (confidential client)
4. Add callback URL: `https://your-worker-name.your-subdomain.workers.dev/callback`
5. Copy the Client ID and Client Secret

### 2. Configure Worker

1. Copy `.dev.vars.example` to `.dev.vars`:
   ```
   X_CLIENT_ID=your_client_id
   X_CLIENT_SECRET=your_client_secret
   ```

2. Update `wrangler.jsonc` with your worker name if needed

### 3. Deploy

```bash
cd x-auth-worker
npm install
npm run deploy
```

Then set production secrets:
```bash
wrangler secret put X_CLIENT_ID
wrangler secret put X_CLIENT_SECRET
```

### 4. Update Extension

After deploying, update the `X_AUTH_WORKER_URL` in `background.js` to match your deployed worker URL.

## How It Works

1. Extension opens `https://worker-url/login`
2. Worker redirects to X OAuth authorization
3. User authorizes the app
4. X redirects back to `https://worker-url/callback`
5. Worker exchanges code for tokens (using secure client_secret)
6. Worker redirects to `/extension-callback?access_token=...`
7. Extension intercepts this URL, extracts tokens, and closes the tab

## Endpoints

- `GET /login` - Start OAuth flow
- `GET /callback` - X OAuth callback (internal)
- `GET /extension-callback` - Extension intercepts this to get tokens
- `POST /refresh` - Refresh access token (body: `{ "refresh_token": "..." }`)
