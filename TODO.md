make `getpromind` backend:

- login with X first. ensure to also have access to bookmarks. This is immediately the first onboarding step
- create dashboard with onboarding flow in a single page that shows a checkmark for every step taken. steps:
  - login with X (button to (re)start x login flow)
  - login with GitHub (button to (re)start github login flow)
  - install chrome extension (let user click "I've done it")
  - install MCP server (let user click "I've done it")
  - subscribe: create stripe subscription of $30/month: prod_U5456bnQ86hgT4. Create a subscription when clicking "Order now with free trial". 7 days free trial.

promo code: FRIENDS100 for 100% discount

TODO:

- ✅ add needed mcp auth endpoints
- ✅ browser history: less items
- ✅ improve search: do additional query per word + allow case insensitivity
- ❌ mcp ui with results; evidence tool with ui (ai can't figure it out)
- try again with https://github.com/janwilmake/mcp-ui-app-without-libs
