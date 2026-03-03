# Twitter Thread

---

**1/**

I built a Chrome extension that gives AI the context of what you're actually doing all day.

No screen recording. No desktop app. Just a lightweight extension that tracks your browsing and makes it queryable.

Here's why 👇

---

**2/**

The problem: you browse hundreds of pages a week and forget most of it.

"I read something about this last week…" — but you can't find it. Your browser history is just a wall of URLs. Useless.

---

**3/**

The fix: passively track your browsing with rich metadata — URLs, titles, descriptions, time spent.

Then expose it to AI via MCP tools.

Now you can just _ask_: "What was that article about vector databases I read on Tuesday?"

Perfect memory. Zero effort.

---

**4/**

Think of it as giving AI eyes into your browsing:

• "Find that pricing page I looked at yesterday"
• "What docs have I been reading about auth?"
• "Make a reading list from everything I browsed this week"

Your history becomes a personal knowledge base — queryable by natural language.

---

**5/**

How it works:

1. Install Chrome extension
2. Login with X (one click)
3. Browse normally
4. AI can now search your history with `search(from, query)` and `fetch(url)`

No config. No screen recording. No OCR. Clean structured data.

---

**6/**

Some details I'm proud of:

• Survives Chrome service worker suspension (persists sessions to storage + uses alarms as keepalive)
• Skips localhost, internal IPs, and browser pages
• Auto-refreshes JWT tokens on 401
• Minimum 5s threshold — no noise from accidental clicks

---

**7/**

vs Screenpipe: they capture everything on screen via OCR. Powerful but heavy.

This is the opposite approach — lightweight, Chrome-only, but the data is _structured_. Clean URLs, exact time-on-site, real page metadata. No fuzzy text extraction.

---

**8/**

What's next:

• Markdown extraction of page content
• AI-generated daily summary of what you worked on
• Team shared context (invite colleagues, reduce meetings)
• Auto-filtering of sensitive URLs via LLM

---

**9/**

The goal: never lose track of something you've seen online again.

Your browsing is already a goldmine of context — it just needs to be accessible.

Open source → github.com/janwilmake/browser-history

---
