# Pro Mind — Your AI with Perfect Memory

A unified app that gives AI tools perfect memory over your browsing history, X bookmarks, and GitHub repos.

## Architecture

```
Chrome Extension  →  getpromind.com  →  Durable Object (per user)
                         ↓
                    X OAuth + GitHub OAuth + Stripe
                    /api/track (browser history)
                    /api/search (unified search)
                    /mcp (MCP endpoint for AI clients)
                    /dashboard (onboarding + search UI)
```

## Data Sources

| Source          | How it syncs                                    | What's stored                                   |
| --------------- | ----------------------------------------------- | ----------------------------------------------- |
| Browser History | Chrome extension sends page visits in real-time | URL, title, description, time spent             |
| X Bookmarks     | Hourly sync via X API (after subscription)      | Tweet text, author, created date                |
| GitHub Repos    | Hourly sync via GitHub API (after subscription) | Repo name, description, stars, language, topics |

## Onboarding Flow

1. Login with X (primary auth, enables bookmarks)
2. Login with GitHub (enables repo sync)
3. Install Chrome extension
4. Set up MCP server in your AI client
5. Subscribe ($30/month, 7-day free trial, promo code FRIENDS100)

## MCP Tools

- `search(query, from?, source?)` — Search across all three data sources
- `fetch(url)` — Fetch content of any URL

## Development

```bash
cd getpromind
npm install
npm run dev
```

## Deploy

```bash
wrangler secret put X_CLIENT_ID
wrangler secret put X_CLIENT_SECRET
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET
wrangler secret put STRIPE_SECRET
wrangler secret put STRIPE_WEBHOOK_SIGNING_SECRET
wrangler secret put STRIPE_PRICE_ID
wrangler secret put JWT_SECRET
npm run deploy
```
