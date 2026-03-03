# Browser History — An AI Connector That Knows What You're Up To

![](worker/public/web-app-manifest-512x512.png)

A Chrome extension that tracks your browsing activity (URLs, titles, time spent) and syncs it to a server — giving AI tools the context they need to actually help you.

![](example.gif)

## Why

- You browse hundreds of pages a week — articles, docs, tools, discussions — and forget most of it
- "I saw something about this last week…" but you can't find it. Your browser history is just a list of URLs with no context
- AI assistants can't help you recall what you've seen because they have zero visibility into your browsing
- **The fix**: passively capture your browsing with rich metadata, then let AI query it. Perfect memory for everything you've read, searchable by natural language

## How It Works

1. **Install the Chrome extension** — no desktop app, no screen recording, no complicated setup
2. **Login with your X (Twitter) account** — one-click authentication
3. **Browse normally** — the extension silently tracks which sites you visit, how long you spend, and page metadata
4. **View your stats** — see your browsing activity on a personal dashboard
5. **AI gets context** — your history becomes queryable via MCP tools (`search(from, query)` + `fetch(url)`)

### What Gets Tracked

- **URL** (normalized, without fragments)
- **Page title** and **meta description**
- **Time spent** on each page (minimum 5 seconds)

### What Doesn't Get Tracked

- Browser internal pages (`chrome://`, `about:`, `edge://`)
- Localhost and private network addresses (`127.x`, `10.x`, `192.168.x`, `172.16-31.x`)
- Visits shorter than 5 seconds

## Architecture

```
Chrome Extension  →  Cloudflare Worker (history.wilmake.com)  →  Storage
      ↓                        ↓
  Popup UI              X OAuth + JWT Auth
  (login, stats)        Tracking API (/api/track)
                        Stats Dashboard (/stats)
                        Token Refresh (/refresh)
```

- **Chrome Extension** (Manifest V3): Background service worker tracks tab switches, URL changes, and window focus. Persists tracking sessions to `chrome.storage.local` to survive service worker suspension. Uses `chrome.alarms` as a keepalive.
- **Backend**: Cloudflare Worker handling auth (X/Twitter OAuth), data ingestion, and a stats dashboard.
- **Auth**: X (Twitter) login → JWT + refresh token flow. Tokens auto-refresh on 401.

## Install

### From Source

1. Clone this repo
2. Open `chrome://extensions` in Chrome
3. Enable **Developer mode**
4. Click **Load unpacked** and select the `chrome-extension/` folder
5. Click the extension icon and log in with X

### Pre-built

Download `chrome-extension.zip` from this repo, unzip, and load as unpacked extension.

## Comparison

### vs [Screenpipe](https://screenpi.pe)

|                   | Browser History                                              | Screenpipe                  |
| ----------------- | ------------------------------------------------------------ | --------------------------- |
| **Scope**         | Chrome only                                                  | All programs + screen       |
| **Data quality**  | Structured: full URL, title, description, exact time on site | OCR-based screen captures   |
| **Privacy model** | Team-oriented shared context                                 | Privacy-first local storage |
| **Install**       | Chrome extension + X login                                   | Desktop app install         |

### vs [Macroscope](https://macroscope.com)

- Broader understanding of what someone is working on, beyond just code
