/// <reference types="@cloudflare/workers-types" />
import { DurableObject } from "cloudflare:workers";
import Stripe from "stripe";

// ============================================================================
// Types
// ============================================================================

export interface Env {
  USER_DO: DurableObjectNamespace<UserDO>;
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  STRIPE_SECRET: string;
  STRIPE_WEBHOOK_SIGNING_SECRET: string;
  STRIPE_PRICE_ID: string;
  JWT_SECRET: string;
}

interface JWTPayload {
  sub: string; // x user id
  username: string;
  exp: number;
}

interface XTokens {
  access_token: string;
  refresh_token?: string;
}

// ============================================================================
// JWT Helpers
// ============================================================================

async function signJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${header}.${body}`)
  );
  const signature = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${body}.${signature}`;
}

async function verifyJWT(
  token: string,
  secret: string
): Promise<JWTPayload | null> {
  try {
    const [header, body, signature] = token.split(".");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = Uint8Array.from(
      atob(signature.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return null;
    const payload: JWTPayload = JSON.parse(
      atob(body.replace(/-/g, "+").replace(/_/g, "/"))
    );
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// ============================================================================
// PKCE Helpers
// ============================================================================

async function generateRandomString(length: number): Promise<string> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ============================================================================
// Cookie helpers
// ============================================================================

function parseCookies(header: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  header.split(";").forEach((c) => {
    const [name, ...rest] = c.trim().split("=");
    if (name && rest.length) cookies[name] = decodeURIComponent(rest.join("="));
  });
  return cookies;
}

function secureCookieFlags(url: URL): string {
  return url.hostname === "localhost" ? "" : "Secure; ";
}

// ============================================================================
// Auth from request
// ============================================================================

async function getAuthFromRequest(
  request: Request,
  env: Env
): Promise<JWTPayload | null> {
  // Try Authorization header (for extension / API)
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return verifyJWT(authHeader.slice(7), env.JWT_SECRET);
  }
  // Try cookie (for dashboard)
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  if (cookies.jwt) {
    return verifyJWT(cookies.jwt, env.JWT_SECRET);
  }
  return null;
}

function getUserDO(env: Env, xUserId: string): DurableObjectStub<UserDO> {
  return env.USER_DO.get(env.USER_DO.idFromName(xUserId));
}

// ============================================================================
// MCP Protocol
// ============================================================================

interface McpAuthCode {
  sub: string;
  username: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  type: "mcp_auth_code";
  exp: number;
}

interface McpAccessToken {
  sub: string;
  username: string;
  scope: string;
  type: "mcp_access";
  iat: number;
}

function mcpToolsList() {
  const today = new Date().toISOString().split("T")[0];
  return [
    {
      name: "search",
      description: `Search across browser history, X bookmarks, and GitHub repos. Returns matching items from all sources. If no query is provided, returns recent items. Today is ${today}.`,
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "Search query (optional — omit to get recent items)"
          },
          from: {
            type: "string",
            description: "ISO date string to search from (optional)"
          },
          until: {
            type: "string",
            description:
              "End date in YYYY-MM-DD format, assumes 23:59:59 for that date (optional)"
          },
          source: {
            type: "string",
            enum: ["all", "history", "bookmarks", "repos"],
            description: "Filter by source (default: all)"
          }
        },
        required: []
      }
    },
    {
      name: "fetch",
      description: "Fetch the content/details of a specific item by URL or ID",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "URL to fetch content for" }
        },
        required: ["url"]
      }
    }
  ];
}

// ============================================================================
// Main Worker
// ============================================================================

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const secure = secureCookieFlags(url);

    // ── Static assets fall through (handled by wrangler assets) ──

    // ── X OAuth ──
    if (path === "/auth/x/login") {
      const state = await generateRandomString(16);
      const codeVerifier = await generateRandomString(43);
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      const redirect_uri = `${url.origin}/auth/x/callback`;

      const authUrl = new URL("https://x.com/i/oauth2/authorize");
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", env.X_CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", redirect_uri);
      authUrl.searchParams.set(
        "scope",
        "bookmark.read tweet.read users.read offline.access"
      );
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      const headers = new Headers({ Location: authUrl.toString() });
      headers.append(
        "Set-Cookie",
        `x_oauth_state=${state}; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=600`
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=600`
      );
      return new Response("Redirecting", { status: 307, headers });
    }

    if (path === "/auth/x/callback") {
      const code = url.searchParams.get("code");
      const urlState = url.searchParams.get("state");
      const cookies = parseCookies(request.headers.get("Cookie") || "");

      if (
        !code ||
        !urlState ||
        urlState !== cookies.x_oauth_state ||
        !cookies.x_code_verifier
      ) {
        return new Response("Invalid OAuth state", { status: 400 });
      }

      const redirect_uri = `${url.origin}/auth/x/callback`;
      const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${btoa(`${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`)}`
        },
        body: new URLSearchParams({
          code,
          client_id: env.X_CLIENT_ID,
          grant_type: "authorization_code",
          redirect_uri,
          code_verifier: cookies.x_code_verifier
        })
      });

      if (!tokenResponse.ok) {
        return new Response(
          `Token exchange failed: ${await tokenResponse.text()}`,
          { status: 500 }
        );
      }

      const tokens = (await tokenResponse.json()) as any;

      // Get user info
      const meRes = await fetch(
        "https://api.x.com/2/users/me?user.fields=profile_image_url",
        {
          headers: { Authorization: `Bearer ${tokens.access_token}` }
        }
      );
      const meData = (await meRes.json()) as any;
      const xUser = meData.data;

      // Create/update user in DO
      const stub = getUserDO(env, xUser.id);
      await stub.setXAuth({
        userId: xUser.id,
        username: xUser.username,
        name: xUser.name,
        profileImageUrl: xUser.profile_image_url,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token
      });

      // Issue JWT
      const jwt = await signJWT(
        {
          sub: xUser.id,
          username: xUser.username,
          exp: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
        },
        env.JWT_SECRET
      );

      const headers = new Headers({ Location: "/dashboard" });
      headers.append(
        "Set-Cookie",
        `x_oauth_state=; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=0`
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=0`
      );
      headers.append(
        "Set-Cookie",
        `jwt=${jwt}; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}`
      );
      return new Response("Redirecting", { status: 302, headers });
    }

    // ── Extension callback (returns JWT for chrome extension to intercept) ──
    if (path === "/extension-callback") {
      // This is just the redirect target the extension intercepts
      return new Response("OK");
    }

    // ── Extension login (redirects to X OAuth, then back to extension-callback) ──
    if (path === "/auth/x/extension-login") {
      const state = await generateRandomString(16);
      const codeVerifier = await generateRandomString(43);
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      const redirect_uri = `${url.origin}/auth/x/extension-callback`;

      const authUrl = new URL("https://x.com/i/oauth2/authorize");
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", env.X_CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", redirect_uri);
      authUrl.searchParams.set(
        "scope",
        "bookmark.read tweet.read users.read offline.access"
      );
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      const headers = new Headers({ Location: authUrl.toString() });
      headers.append(
        "Set-Cookie",
        `x_oauth_state=${state}; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=600`
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=600`
      );
      return new Response("Redirecting", { status: 307, headers });
    }

    if (path === "/auth/x/extension-callback") {
      const code = url.searchParams.get("code");
      const urlState = url.searchParams.get("state");
      const cookies = parseCookies(request.headers.get("Cookie") || "");

      if (
        !code ||
        !urlState ||
        urlState !== cookies.x_oauth_state ||
        !cookies.x_code_verifier
      ) {
        return new Response("Invalid OAuth state", { status: 400 });
      }

      const redirect_uri = `${url.origin}/auth/x/extension-callback`;
      const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${btoa(`${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`)}`
        },
        body: new URLSearchParams({
          code,
          client_id: env.X_CLIENT_ID,
          grant_type: "authorization_code",
          redirect_uri,
          code_verifier: cookies.x_code_verifier
        })
      });

      if (!tokenResponse.ok) {
        return new Response(`Token exchange failed`, { status: 500 });
      }

      const tokens = (await tokenResponse.json()) as any;
      const meRes = await fetch(
        "https://api.x.com/2/users/me?user.fields=profile_image_url",
        {
          headers: { Authorization: `Bearer ${tokens.access_token}` }
        }
      );
      const meData = (await meRes.json()) as any;
      const xUser = meData.data;

      const stub = getUserDO(env, xUser.id);
      await stub.setXAuth({
        userId: xUser.id,
        username: xUser.username,
        name: xUser.name,
        profileImageUrl: xUser.profile_image_url,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token
      });

      const jwt = await signJWT(
        {
          sub: xUser.id,
          username: xUser.username,
          exp: Date.now() + 30 * 24 * 60 * 60 * 1000
        },
        env.JWT_SECRET
      );

      const callbackUrl = new URL(`${url.origin}/extension-callback`);
      callbackUrl.searchParams.set("jwt", jwt);
      callbackUrl.searchParams.set("refresh_token", tokens.refresh_token || "");
      callbackUrl.searchParams.set(
        "user",
        JSON.stringify({
          id: xUser.id,
          username: xUser.username,
          name: xUser.name,
          profile_image_url: xUser.profile_image_url
        })
      );

      const headers = new Headers({ Location: callbackUrl.toString() });
      headers.append("Set-Cookie", `x_oauth_state=; Path=/; Max-Age=0`);
      headers.append("Set-Cookie", `x_code_verifier=; Path=/; Max-Age=0`);
      return new Response("Redirecting", { status: 302, headers });
    }

    // ── Refresh JWT (for extension) ──
    if (path === "/auth/refresh" && request.method === "POST") {
      const body = (await request.json()) as any;
      const refreshToken = body.refresh_token;
      if (!refreshToken)
        return Response.json(
          { error: "Missing refresh_token" },
          { status: 400 }
        );

      const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${btoa(`${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`)}`
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: env.X_CLIENT_ID
        })
      });

      if (!tokenResponse.ok) {
        return Response.json({ error: "Refresh failed" }, { status: 401 });
      }

      const tokens = (await tokenResponse.json()) as any;
      const meRes = await fetch(
        "https://api.x.com/2/users/me?user.fields=profile_image_url",
        {
          headers: { Authorization: `Bearer ${tokens.access_token}` }
        }
      );
      const meData = (await meRes.json()) as any;
      const xUser = meData.data;

      const stub = getUserDO(env, xUser.id);
      await stub.setXAuth({
        userId: xUser.id,
        username: xUser.username,
        name: xUser.name,
        profileImageUrl: xUser.profile_image_url,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token || refreshToken
      });

      const jwt = await signJWT(
        {
          sub: xUser.id,
          username: xUser.username,
          exp: Date.now() + 30 * 24 * 60 * 60 * 1000
        },
        env.JWT_SECRET
      );

      return Response.json({
        jwt,
        refresh_token: tokens.refresh_token || refreshToken,
        user: {
          id: xUser.id,
          username: xUser.username,
          name: xUser.name,
          profile_image_url: xUser.profile_image_url
        }
      });
    }

    // ── GitHub OAuth ──
    if (path === "/auth/github/login") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth)
        return new Response("Login with X first", {
          status: 401,
          headers: { Location: "/dashboard" }
        });

      const state = await generateRandomString(16);
      const ghUrl = new URL("https://github.com/login/oauth/authorize");
      ghUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      ghUrl.searchParams.set(
        "redirect_uri",
        `${url.origin}/auth/github/callback`
      );
      ghUrl.searchParams.set("scope", "user:email repo");
      ghUrl.searchParams.set("state", state);

      const headers = new Headers({ Location: ghUrl.toString() });
      headers.append(
        "Set-Cookie",
        `gh_oauth_state=${state}; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=600`
      );
      headers.append(
        "Set-Cookie",
        `gh_x_user_id=${auth.sub}; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=600`
      );
      return new Response("Redirecting", { status: 307, headers });
    }

    if (path === "/auth/github/callback") {
      const code = url.searchParams.get("code");
      const urlState = url.searchParams.get("state");
      const cookies = parseCookies(request.headers.get("Cookie") || "");

      if (
        !code ||
        !urlState ||
        urlState !== cookies.gh_oauth_state ||
        !cookies.gh_x_user_id
      ) {
        return new Response("Invalid OAuth state", { status: 400 });
      }

      const tokenResponse = await fetch(
        "https://github.com/login/oauth/access_token",
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            client_id: env.GITHUB_CLIENT_ID,
            client_secret: env.GITHUB_CLIENT_SECRET,
            code,
            redirect_uri: `${url.origin}/auth/github/callback`
          })
        }
      );

      const tokenData = (await tokenResponse.json()) as any;
      if (!tokenData.access_token) {
        return new Response("Failed to get GitHub token", { status: 400 });
      }

      const ghUserRes = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: "application/vnd.github.v3+json",
          "User-Agent": "ProMind"
        }
      });
      const ghUser = (await ghUserRes.json()) as any;

      const stub = getUserDO(env, cookies.gh_x_user_id);
      await stub.setGitHubAuth({
        login: ghUser.login,
        id: ghUser.id,
        avatarUrl: ghUser.avatar_url,
        accessToken: tokenData.access_token
      });

      const headers = new Headers({ Location: "/dashboard" });
      headers.append("Set-Cookie", `gh_oauth_state=; Path=/; Max-Age=0`);
      headers.append("Set-Cookie", `gh_x_user_id=; Path=/; Max-Age=0`);
      return new Response("Redirecting", { status: 302, headers });
    }

    // ── Logout ──
    if (path === "/auth/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie": `jwt=; HttpOnly; Path=/; ${secure}SameSite=Lax; Max-Age=0`
        }
      });
    }

    // ── Stripe webhook ──
    if (path === "/webhook/stripe" && request.method === "POST") {
      const stripe = new Stripe(env.STRIPE_SECRET, {
        apiVersion: "2025-12-15.clover"
      });
      const rawBody = await request.text();
      const sig = request.headers.get("stripe-signature");
      if (!sig)
        return Response.json({ error: "No signature" }, { status: 400 });

      let event: Stripe.Event;
      try {
        event = await stripe.webhooks.constructEventAsync(
          rawBody,
          sig,
          env.STRIPE_WEBHOOK_SIGNING_SECRET
        );
      } catch (err: any) {
        return Response.json({ error: err.message }, { status: 400 });
      }

      const webhookRegistry = env.USER_DO.get(
        env.USER_DO.idFromName("__registry__")
      );

      if (event.type === "checkout.session.completed") {
        const session = event.data.object as Stripe.Checkout.Session;
        if (session.payment_status === "paid" && session.client_reference_id) {
          // client_reference_id is the X user ID
          const stub = getUserDO(env, session.client_reference_id);
          await stub.activateSubscription(
            session.customer as string,
            session.subscription as string
          );
          await webhookRegistry.updateUserStats(
            session.client_reference_id,
            "is_subscribed",
            1
          );
        }
      }

      if (event.type === "customer.subscription.deleted") {
        const subscription = event.data.object as Stripe.Subscription;
        if (subscription.metadata?.x_user_id) {
          const stub = getUserDO(env, subscription.metadata.x_user_id);
          await stub.deactivateSubscription();
          await webhookRegistry.updateUserStats(
            subscription.metadata.x_user_id,
            "is_subscribed",
            0
          );
        }
      }

      if (event.type === "invoice.payment_failed") {
        const invoice = event.data.object as Stripe.Invoice;
        if (invoice.subscription_details?.metadata?.x_user_id) {
          const xUserId = invoice.subscription_details.metadata.x_user_id;
          const stub = getUserDO(env, xUserId);
          await stub.deactivateSubscription();
          await webhookRegistry.updateUserStats(xUserId, "is_subscribed", 0);
        }
      }

      return Response.json({ received: true });
    }

    // ── Create Stripe checkout ──
    if (path === "/api/create-checkout" && request.method === "POST") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth)
        return Response.json({ error: "Unauthorized" }, { status: 401 });

      const stripe = new Stripe(env.STRIPE_SECRET, {
        apiVersion: "2025-12-15.clover"
      });
      const session = await stripe.checkout.sessions.create({
        mode: "subscription",
        payment_method_types: ["card"],
        line_items: [{ price: env.STRIPE_PRICE_ID, quantity: 1 }],
        subscription_data: {
          trial_period_days: 7,
          metadata: { x_user_id: auth.sub }
        },
        client_reference_id: auth.sub,
        success_url: `${url.origin}/dashboard?subscribed=true`,
        cancel_url: `${url.origin}/dashboard`,
        allow_promotion_codes: true
      });

      return Response.json({ url: session.url });
    }

    // ── API: Track browsing (from extension) ──
    if (path === "/api/track" && request.method === "POST") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth)
        return Response.json({ error: "Unauthorized" }, { status: 401 });

      const stub = getUserDO(env, auth.sub);
      const isActive = await stub.isSubscriptionActive();
      if (!isActive)
        return Response.json(
          { error: "Subscription required" },
          { status: 403 }
        );

      const body = (await request.json()) as any;
      await stub.trackVisit({
        url: body.domain || body.url,
        title: body.title || "",
        description: body.description || "",
        duration: body.duration || 0,
        timestamp: Date.now()
      });

      // Update registry stats
      const registry = env.USER_DO.get(env.USER_DO.idFromName("__registry__"));
      await registry.updateUserStats(auth.sub, "last_history_at", Date.now());

      return Response.json({ ok: true });
    }

    // ── API: Get onboarding status ──
    if (path === "/api/status") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth)
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      const stub = getUserDO(env, auth.sub);
      const status = await stub.getOnboardingStatus();
      return Response.json(status);
    }

    // ── API: Mark step done ──
    if (path === "/api/mark-step" && request.method === "POST") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth)
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      const body = (await request.json()) as any;
      const stub = getUserDO(env, auth.sub);
      await stub.markStep(body.step);
      return Response.json({ ok: true });
    }

    // ── API: MCP search ──
    if (path === "/api/search") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth)
        return Response.json({ error: "Unauthorized" }, { status: 401 });

      const query = url.searchParams.get("q") || "";
      const from = url.searchParams.get("from") || "";
      const until = url.searchParams.get("until") || "";
      const source = url.searchParams.get("source") || "all";

      const stub = getUserDO(env, auth.sub);
      const results = await stub.search(query, from, until, source);
      return Response.json(results);
    }

    // ── API: Stats page (for extension "view stats" button) ──
    if (path === "/stats") {
      const token = url.searchParams.get("token");
      if (!token) return new Response("Missing token", { status: 401 });
      const auth = await verifyJWT(token, env.JWT_SECRET);
      if (!auth) return new Response("Invalid token", { status: 401 });
      return new Response(null, {
        status: 302,
        headers: { Location: "/dashboard" }
      });
    }

    // ── .well-known MCP OAuth endpoints ──
    if (path === "/.well-known/oauth-protected-resource") {
      return Response.json({
        resource: url.origin,
        authorization_servers: [url.origin],
        scopes_supported: ["history:read", "fetch:read"],
        bearer_methods_supported: ["header"]
      });
    }

    if (path === "/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer: url.origin,
        authorization_endpoint: `${url.origin}/mcp/authorize`,
        token_endpoint: `${url.origin}/mcp/token`,
        registration_endpoint: `${url.origin}/mcp/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["history:read", "fetch:read"],
        client_id_metadata_document_supported: true
      });
    }

    // ── MCP OAuth: Dynamic client registration ──
    if (path === "/mcp/register" && request.method === "POST") {
      const body = (await request.json()) as {
        client_name?: string;
        redirect_uris?: string[];
        grant_types?: string[];
        response_types?: string[];
        token_endpoint_auth_method?: string;
      };
      const clientId = `client_${crypto.randomUUID()}`;
      return Response.json(
        {
          client_id: clientId,
          client_name: body.client_name || "MCP Client",
          redirect_uris: body.redirect_uris || [],
          grant_types: body.grant_types || ["authorization_code"],
          response_types: body.response_types || ["code"],
          token_endpoint_auth_method: body.token_endpoint_auth_method || "none"
        },
        { status: 201 }
      );
    }

    // ── MCP OAuth: Authorization endpoint ──
    if (path === "/mcp/authorize" && request.method === "GET") {
      const responseType = url.searchParams.get("response_type");
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const scope = url.searchParams.get("scope") || "history:read fetch:read";
      const state = url.searchParams.get("state");
      const codeChallenge = url.searchParams.get("code_challenge");
      const codeChallengeMethod = url.searchParams.get("code_challenge_method");

      if (
        responseType !== "code" ||
        !clientId ||
        !redirectUri ||
        !codeChallenge
      ) {
        return Response.json(
          {
            error: "invalid_request",
            error_description:
              "Missing required parameters: response_type=code, client_id, redirect_uri, code_challenge"
          },
          { status: 400 }
        );
      }

      if (codeChallengeMethod && codeChallengeMethod !== "S256") {
        return Response.json(
          {
            error: "invalid_request",
            error_description: "Only S256 code_challenge_method is supported"
          },
          { status: 400 }
        );
      }

      // Check for existing JWT session
      const cookies = parseCookies(request.headers.get("Cookie") || "");
      const payload = cookies.jwt
        ? await verifyJWT(cookies.jwt, env.JWT_SECRET)
        : null;

      if (!payload) {
        // User needs to sign in first
        const html = `<!DOCTYPE html>
<html><head><title>MCP Authorization</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
  .container { text-align: center; padding: 40px; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; }
  h1 { margin: 0 0 8px 0; color: #333; font-size: 20px; }
  p { color: #666; margin: 0 0 20px 0; font-size: 14px; }
  a.btn { display: inline-block; padding: 12px 24px; background: #1da1f2; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; }
  a.btn:hover { background: #0d8ecf; }
</style></head><body>
<div class="container">
  <h1>Sign in required</h1>
  <p>An MCP client wants to access Pro Mind. Please sign in first, then return to this page.</p>
  <a class="btn" href="/auth/x/login">Sign in with X</a>
</div></body></html>`;
        return new Response(html, {
          headers: { "Content-Type": "text/html;charset=utf-8" }
        });
      }

      // User is authenticated — issue auth code as signed JWT
      const authCode: McpAuthCode = {
        sub: payload.sub,
        username: payload.username,
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: codeChallenge,
        scope,
        type: "mcp_auth_code",
        exp: Date.now() + 5 * 60 * 1000 // 5 minutes
      };

      const code = await signJWT(
        authCode as unknown as JWTPayload,
        env.JWT_SECRET
      );

      const redirect = new URL(redirectUri);
      redirect.searchParams.set("code", code);
      if (state) redirect.searchParams.set("state", state);

      return new Response(null, {
        status: 302,
        headers: { Location: redirect.toString() }
      });
    }

    // ── MCP OAuth: Token endpoint ──
    if (path === "/mcp/token" && request.method === "POST") {
      let params: URLSearchParams;
      const contentType = request.headers.get("Content-Type") || "";
      if (contentType.includes("application/json")) {
        const body = (await request.json()) as Record<string, string>;
        params = new URLSearchParams(body);
      } else {
        params = new URLSearchParams(await request.text());
      }

      const grantType = params.get("grant_type");
      const code = params.get("code");
      const redirectUri = params.get("redirect_uri");
      const clientId = params.get("client_id");
      const codeVerifier = params.get("code_verifier");

      if (grantType !== "authorization_code" || !code || !codeVerifier) {
        return Response.json(
          {
            error: "invalid_request",
            error_description:
              "Missing required parameters: grant_type=authorization_code, code, code_verifier"
          },
          { status: 400 }
        );
      }

      const authCode = (await verifyJWT(
        code,
        env.JWT_SECRET
      )) as unknown as McpAuthCode | null;

      if (!authCode || authCode.type !== "mcp_auth_code") {
        return Response.json(
          {
            error: "invalid_grant",
            error_description: "Invalid or expired authorization code"
          },
          { status: 400 }
        );
      }

      if (authCode.exp < Date.now()) {
        return Response.json(
          {
            error: "invalid_grant",
            error_description: "Authorization code has expired"
          },
          { status: 400 }
        );
      }

      if (clientId && clientId !== authCode.client_id) {
        return Response.json(
          {
            error: "invalid_grant",
            error_description: "client_id mismatch"
          },
          { status: 400 }
        );
      }

      if (redirectUri && redirectUri !== authCode.redirect_uri) {
        return Response.json(
          {
            error: "invalid_grant",
            error_description: "redirect_uri mismatch"
          },
          { status: 400 }
        );
      }

      // Verify PKCE S256
      const challengeFromVerifier = await generateCodeChallenge(codeVerifier);
      if (challengeFromVerifier !== authCode.code_challenge) {
        return Response.json(
          {
            error: "invalid_grant",
            error_description: "PKCE verification failed"
          },
          { status: 400 }
        );
      }

      // Issue access token
      const accessToken: McpAccessToken = {
        sub: authCode.sub,
        username: authCode.username,
        scope: authCode.scope,
        type: "mcp_access",
        iat: Date.now()
      };

      const token = await signJWT(
        accessToken as unknown as JWTPayload,
        env.JWT_SECRET
      );

      return Response.json({
        access_token: token,
        token_type: "bearer",
        scope: authCode.scope
      });
    }

    // ── MCP endpoint ──
    if (path === "/mcp") {
      const origin = url.origin;
      const mcpCorsHeaders = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "Mcp-Session-Id"
      };

      // OPTIONS
      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers":
              "Content-Type, Authorization, Mcp-Session-Id"
          }
        });
      }

      // Validate Bearer token (accept both MCP access tokens and regular JWTs)
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response("", {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
            ...mcpCorsHeaders
          }
        });
      }

      const tokenStr = authHeader.slice(7);
      const tokenPayload = await verifyJWT(tokenStr, env.JWT_SECRET);
      // Also try as McpAccessToken
      const mcpToken = tokenPayload as unknown as McpAccessToken | null;
      const isMcpToken = mcpToken?.type === "mcp_access";

      if (!tokenPayload && !isMcpToken) {
        return new Response("", {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
            ...mcpCorsHeaders
          }
        });
      }

      const authSub = tokenPayload!.sub;

      // GET /mcp
      if (request.method === "GET") {
        return Response.json(
          {
            jsonrpc: "2.0",
            error: { code: -32600, message: "Use POST for MCP requests" }
          },
          {
            status: 405,
            headers: { "Content-Type": "application/json", ...mcpCorsHeaders }
          }
        );
      }

      // DELETE /mcp - session termination
      if (request.method === "DELETE") {
        return new Response(null, { status: 200, headers: mcpCorsHeaders });
      }

      // POST /mcp - JSON-RPC
      if (request.method === "POST") {
        const body = (await request.json()) as {
          jsonrpc: string;
          id?: string | number;
          method: string;
          params?: Record<string, unknown>;
        };

        const sessionId =
          request.headers.get("Mcp-Session-Id") || crypto.randomUUID();

        const respond = (result: unknown) =>
          Response.json(
            { jsonrpc: "2.0", id: body.id, result },
            {
              headers: {
                "Content-Type": "application/json",
                "Mcp-Session-Id": sessionId,
                ...mcpCorsHeaders
              }
            }
          );

        const respondError = (code: number, message: string) =>
          Response.json(
            { jsonrpc: "2.0", id: body.id, error: { code, message } },
            {
              headers: {
                "Content-Type": "application/json",
                "Mcp-Session-Id": sessionId,
                ...mcpCorsHeaders
              }
            }
          );

        switch (body.method) {
          case "initialize":
            return respond({
              protocolVersion: "2025-03-26",
              capabilities: { tools: {} },
              serverInfo: { name: "promind", version: "1.0.0" }
            });

          case "notifications/initialized":
            return new Response(null, {
              status: 204,
              headers: { "Mcp-Session-Id": sessionId, ...mcpCorsHeaders }
            });

          case "tools/list":
            return respond({ tools: mcpToolsList() });

          case "tools/call": {
            const toolName = (body.params as { name: string })?.name;
            const args =
              (body.params as { arguments?: Record<string, unknown> })
                ?.arguments || {};
            const stub = getUserDO(env, authSub);

            // Update registry stats
            const mcpRegistry = env.USER_DO.get(
              env.USER_DO.idFromName("__registry__")
            );
            mcpRegistry.updateUserStats(authSub, "last_mcp_at", Date.now());

            if (toolName === "search") {
              const results = await stub.search(
                (args.query as string) || "",
                (args.from as string) || "",
                (args.until as string) || "",
                (args.source as string) || "all"
              );
              return respond({
                content: [
                  { type: "text", text: JSON.stringify(results, null, 2) }
                ]
              });
            }

            if (toolName === "fetch") {
              const fetchUrl = args.url as string;
              if (!fetchUrl) {
                return respondError(-32602, "Missing required parameter: url");
              }
              try {
                const res = await fetch(fetchUrl, {
                  headers: { "User-Agent": "ProMind-MCP/1.0" }
                });
                const text = await res.text();
                const content =
                  text.length > 50000
                    ? text.slice(0, 50000) + "\n...(truncated)"
                    : text;
                return respond({
                  content: [{ type: "text", text: content }]
                });
              } catch (err: any) {
                return respond({
                  content: [
                    {
                      type: "text",
                      text: `Fetch error: ${err.message}`
                    }
                  ],
                  isError: true
                });
              }
            }

            return respondError(-32602, `Unknown tool: ${toolName}`);
          }

          default:
            return respondError(-32601, `Method not found: ${body.method}`);
        }
      }

      return new Response(null, { status: 405, headers: mcpCorsHeaders });
    }

    // ── Dashboard (setup) ──
    if (path === "/dashboard") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth) {
        return new Response(null, {
          status: 302,
          headers: { Location: "/auth/x/login" }
        });
      }
      const stub = getUserDO(env, auth.sub);
      const status = await stub.getOnboardingStatus();

      return new Response(renderDashboard(status, url.origin), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // ── Search page ──
    if (path === "/search") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth) {
        return new Response(null, {
          status: 302,
          headers: { Location: "/auth/x/login" }
        });
      }
      const stub = getUserDO(env, auth.sub);
      const status = await stub.getOnboardingStatus();

      return new Response(renderSearchPage(status, url.origin), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // ── Daily digest (for public URL sharing) ──
    if (path.startsWith("/api/daily/")) {
      const auth = await getAuthFromRequest(request, env);
      if (!auth)
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      const stub = getUserDO(env, auth.sub);
      const date =
        path.split("/").pop() || new Date().toISOString().slice(0, 10);
      const results = await stub.getDailySummary(date);
      return Response.json(results);
    }

    // ── Admin: list all users ──
    if (path === "/admin") {
      const auth = await getAuthFromRequest(request, env);
      if (!auth || auth.username !== "janwilmake")
        return Response.json({ error: "Forbidden" }, { status: 403 });
      const registry = env.USER_DO.get(env.USER_DO.idFromName("__registry__"));
      const users = await registry.getAllUsers();
      return new Response(JSON.stringify({ users }, undefined, 2));
    }

    // Fall through to static assets (index.html etc)
    return new Response("Not Found", { status: 404 });
  },

  async scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext) {
    // This runs hourly. We need a way to iterate all users.
    // Since DOs are keyed by X user ID, we need a registry.
    // We'll use a special "registry" DO to track all user IDs.
    const registry = env.USER_DO.get(env.USER_DO.idFromName("__registry__"));
    const userIds = await registry.getAllUserIds();
    for (const userId of userIds) {
      try {
        const stub = getUserDO(env, userId);
        const isActive = await stub.isSubscriptionActive();
        if (isActive) {
          await stub.syncAllData();
        }
      } catch (e) {
        console.error(`Sync failed for ${userId}:`, e);
      }
    }
  }
} satisfies ExportedHandler<Env>;

// ============================================================================
// Dashboard HTML renderer
// ============================================================================

function renderDashboard(status: OnboardingStatus, origin: string): string {
  const check = (done: boolean) =>
    done ? `<span class="check done">✓</span>` : `<span class="check">○</span>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pro Mind — Dashboard</title>
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="shortcut icon" href="/favicon.ico" />
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
  <link rel="manifest" href="/site.webmanifest" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Helvetica Neue', sans-serif; background: #000; color: #fff; -webkit-font-smoothing: antialiased; }
    .container { max-width: 640px; margin: 0 auto; padding: 40px 24px; }
    .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
    .header h1 { font-size: 24px; font-weight: 600; letter-spacing: -0.5px; }
    .user-info { display: flex; align-items: center; gap: 12px; }
    .user-info img { width: 36px; height: 36px; border-radius: 50%; }
    .user-info a { color: #86868b; text-decoration: none; font-size: 14px; }
    .nav { display: flex; gap: 8px; margin-bottom: 32px; }
    .nav a { padding: 8px 16px; border-radius: 980px; font-size: 14px; font-weight: 500; text-decoration: none; color: #86868b; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); }
    .nav a.active { background: #fff; color: #000; border-color: #fff; }
    .steps { display: flex; flex-direction: column; gap: 16px; }
    .step { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 24px; }
    .step.completed { border-color: rgba(52,199,89,0.3); }
    .step-header { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
    .check { font-size: 20px; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 50%; background: rgba(255,255,255,0.1); color: #86868b; flex-shrink: 0; }
    .check.done { background: rgba(52,199,89,0.2); color: #34c759; }
    .step-title { font-size: 17px; font-weight: 600; }
    .step-desc { font-size: 14px; color: #86868b; line-height: 1.5; margin-left: 48px; margin-bottom: 16px; }
    .step-action { margin-left: 48px; }
    .btn { display: inline-block; padding: 10px 20px; border-radius: 980px; font-size: 14px; font-weight: 500; text-decoration: none; cursor: pointer; border: none; }
    .btn-primary { background: #fff; color: #000; }
    .btn-secondary { background: rgba(255,255,255,0.1); color: #fff; }
    .btn-green { background: #34c759; color: #fff; }
    .btn:hover { opacity: 0.85; }
    .mcp-section { margin-top: 24px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 16px; }
    .mcp-section h3 { font-size: 15px; font-weight: 600; margin-bottom: 8px; }
    .mcp-section code { background: rgba(255,255,255,0.1); padding: 8px 12px; border-radius: 8px; display: block; font-size: 13px; word-break: break-all; color: #86868b; }
    .stats { display: flex; gap: 16px; margin-top: 24px; flex-wrap: wrap; }
    .stat { flex: 1; min-width: 120px; background: rgba(255,255,255,0.05); border-radius: 12px; padding: 16px; text-align: center; }
    .stat-value { font-size: 28px; font-weight: 700; }
    .stat-label { font-size: 12px; color: #86868b; margin-top: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1><img src="/favicon-96x96.png" alt="Pro Mind" style="width:28px;height:28px;vertical-align:middle;margin-right:8px;">Pro Mind</h1>
      <div class="user-info">
        ${status.xUser ? `<img src="${status.xUser.profileImageUrl}" alt="">` : ""}
        <span>${status.xUser?.username || "Unknown"}</span>
        <a href="/auth/logout">Logout</a>
      </div>
    </div>

    <div class="nav">
      <a href="/dashboard" class="active">Setup</a>
      <a href="/search">Search</a>
    </div>

    <div class="steps">
      <!-- Step 1: Login with X -->
      <div class="step ${status.xConnected ? "completed" : ""}">
        <div class="step-header">
          ${check(status.xConnected)}
          <div class="step-title">Login with X</div>
        </div>
        <div class="step-desc">Connect your X account to sync bookmarks and authenticate.</div>
        ${!status.xConnected ? `<div class="step-action"><a href="/auth/x/login" class="btn btn-primary">Connect X</a></div>` : ""}
      </div>

      <!-- Step 2: Login with GitHub -->
      <div class="step ${status.githubConnected ? "completed" : ""}">
        <div class="step-header">
          ${check(status.githubConnected)}
          <div class="step-title">Login with GitHub</div>
        </div>
        <div class="step-desc">Connect GitHub to make your repos searchable by AI.</div>
        <div class="step-action">
          ${
            !status.githubConnected
              ? `<a href="/auth/github/login" class="btn btn-primary">Connect GitHub</a>`
              : `<span style="color:#34c759;font-size:14px;">Connected as ${status.githubUser?.login || ""}</span>`
          }
        </div>
      </div>

      <!-- Step 3: Install Chrome Extension -->
      <div class="step ${status.extensionInstalled ? "completed" : ""}">
        <div class="step-header">
          ${check(status.extensionInstalled)}
          <div class="step-title">Install Chrome Extension</div>
        </div>
        <div class="step-desc">Track your browsing history for AI recall. The extension sends page URLs, titles, and time spent.</div>
        <div class="step-action">
          <a href="/chrome-extension.zip" target="_blank" class="btn btn-secondary" style="margin-right:8px;">Download Extension</a>
          ${
            !status.extensionInstalled
              ? `<button class="btn btn-secondary" onclick="markStep('extension')">I've installed it</button>`
              : ""
          }
        </div>
      </div>

      <!-- Step 4: Install MCP Server -->
      <div class="step ${status.mcpInstalled ? "completed" : ""}">
        <div class="step-header">
          ${check(status.mcpInstalled)}
          <div class="step-title">Install MCP Server</div>
        </div>
        <div class="step-desc">Connect Pro Mind to Claude, Cursor, or any MCP-compatible AI client.</div>
        <div class="mcp-section">
          <h3>MCP URL</h3>
          <code id="mcp-url">${origin}/mcp</code>
          <div style="margin-top:12px;">
            <a href="https://installthismcp.com/ProMind?url=${encodeURIComponent(origin + "/mcp")}" target="_blank" class="btn btn-secondary" style="text-decoration:none;display:inline-block;">Install MCP Server</a>
          </div>
        </div>
        <div class="step-action" style="margin-top:12px;">
          ${
            !status.mcpInstalled
              ? `<button class="btn btn-secondary" onclick="markStep('mcp')">I've set it up</button>`
              : ""
          }
        </div>
      </div>

      <!-- Step 5: Subscribe -->
      <div class="step ${status.subscribed ? "completed" : ""}">
        <div class="step-header">
          ${check(status.subscribed)}
          <div class="step-title">Subscribe</div>
        </div>
        <div class="step-desc">$30/month with 7-day free trial. Hourly X bookmark and GitHub repo syncing, unlimited browser history tracking, and instant search across all sources via MCP.</div>
        <div class="step-action">
          ${
            !status.subscribed
              ? `<button class="btn btn-green" onclick="subscribe()">Start Free Trial</button>`
              : `<span style="color:#34c759;font-size:14px;">Active subscription ✓</span>`
          }
        </div>
      </div>
    </div>

    ${
      status.subscribed
        ? `
    <div class="stats">
      <div class="stat">
        <div class="stat-value">${status.historyCount}</div>
        <div class="stat-label">Pages Tracked</div>
      </div>
      <div class="stat">
        <div class="stat-value">${status.bookmarkCount}</div>
        <div class="stat-label">Bookmarks</div>
      </div>
      <div class="stat">
        <div class="stat-value">${status.repoCount}</div>
        <div class="stat-label">Repos</div>
      </div>
    </div>
    `
        : ""
    }
  </div>

  <script>
    async function markStep(step) {
      await fetch('/api/mark-step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ step })
      });
      location.reload();
    }

    async function subscribe() {
      const res = await fetch('/api/create-checkout', { method: 'POST' });
      const data = await res.json();
      if (data.url) window.location.href = data.url;
      else alert('Error creating checkout: ' + JSON.stringify(data));
    }

  </script>
</body>
</html>`;
}

// ============================================================================
// Search Page HTML renderer
// ============================================================================

function renderSearchPage(status: OnboardingStatus, origin: string): string {
  const isSubscribed = status.subscribed;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pro Mind — Search</title>
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="shortcut icon" href="/favicon.ico" />
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
  <link rel="manifest" href="/site.webmanifest" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; overflow: hidden; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Helvetica Neue', sans-serif; background: #000; color: #fff; -webkit-font-smoothing: antialiased; display: flex; flex-direction: column; }
    .container { max-width: 640px; width: 100%; margin: 0 auto; padding: 40px 24px 0; display: flex; flex-direction: column; flex: 1; min-height: 0; }
    .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
    .header h1 { font-size: 24px; font-weight: 600; letter-spacing: -0.5px; }
    .user-info { display: flex; align-items: center; gap: 12px; }
    .user-info img { width: 36px; height: 36px; border-radius: 50%; }
    .user-info a { color: #86868b; text-decoration: none; font-size: 14px; }
    .nav { display: flex; gap: 8px; margin-bottom: 32px; }
    .nav a { padding: 8px 16px; border-radius: 980px; font-size: 14px; font-weight: 500; text-decoration: none; color: #86868b; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); }
    .nav a.active { background: #fff; color: #000; border-color: #fff; }
    .search-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-shrink: 0; }
    .search-bar input { flex: 1; padding: 10px 16px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.05); color: #fff; font-size: 14px; outline: none; }
    .search-bar input:focus { border-color: rgba(255,255,255,0.4); }
    .search-bar button { padding: 10px 20px; border-radius: 12px; background: #fff; color: #000; border: none; font-size: 14px; font-weight: 500; cursor: pointer; }
    .search-bar button:disabled { background: rgba(255,255,255,0.1); color: #86868b; cursor: not-allowed; }
    .results { flex: 1; overflow-y: auto; min-height: 0; padding-bottom: 24px; }
    .result-item { padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.06); }
    .result-source { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 4px; }
    .source-history { background: rgba(52,199,89,0.2); color: #34c759; }
    .source-bookmarks { background: rgba(0,122,255,0.2); color: #007aff; }
    .source-repos { background: rgba(255,149,0,0.2); color: #ff9500; }
    .result-title { font-size: 14px; font-weight: 500; color: #fff; }
    .result-meta { font-size: 12px; color: #86868b; margin-top: 2px; }
    .result-title a { color: #fff; text-decoration: none; }
    .result-title a:hover { text-decoration: underline; }
    .result-url { font-size: 12px; color: #555; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .upgrade-notice { text-align: center; padding: 48px 24px; color: #86868b; }
    .upgrade-notice a { color: #fff; text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1><img src="/favicon-96x96.png" alt="Pro Mind" style="width:28px;height:28px;vertical-align:middle;margin-right:8px;">Pro Mind</h1>
      <div class="user-info">
        ${status.xUser ? `<img src="${status.xUser.profileImageUrl}" alt="">` : ""}
        <span>${status.xUser?.username || "Unknown"}</span>
        <a href="/auth/logout">Logout</a>
      </div>
    </div>

    <div class="nav">
      <a href="/dashboard">Setup</a>
      <a href="/search" class="active">Search</a>
    </div>

    <div class="search-bar">
      <input type="text" id="search-input" placeholder="youtube" onkeydown="if(event.key==='Enter')doSearch()">
      <button onclick="doSearch()" ${!isSubscribed ? "disabled" : ""}>Search</button>
    </div>

    ${
      !isSubscribed
        ? `<div class="upgrade-notice">Subscribe to search your memory. <a href="/dashboard">Go to Setup</a> to start your free trial.</div>`
        : ""
    }

    <div class="results" id="results"></div>
  </div>

  <script>
    async function doSearch() {
      ${!isSubscribed ? "return;" : ""}
      const q = document.getElementById('search-input').value;
      if (!q.trim()) return;
      const res = await fetch('/api/search?q=' + encodeURIComponent(q));
      const results = await res.json();

      const container = document.getElementById('results');
      if (!results.length) {
        container.innerHTML = '<div style="padding:24px;text-align:center;color:#86868b;">No results found</div>';
        return;
      }

      container.innerHTML = results.map(r => {
        const sourceClass = r.source === 'history' ? 'source-history' : r.source === 'bookmarks' ? 'source-bookmarks' : 'source-repos';
        var favicon = '';
        try { if (r.url) { var h = new URL(r.url).hostname; favicon = '<img src="https://www.google.com/s2/favicons?domain=' + h + '&sz=32" width="16" height="16" style="vertical-align:middle;margin-right:8px;border-radius:2px;">'; } } catch(e) {}
        return '<div class="result-item">' +
          '<span class="result-source ' + sourceClass + '">' + r.source + '</span>' +
          '<div class="result-title">' + favicon + '<a href="' + (r.url || '#') + '" target="_blank">' + escapeHtml(r.title || r.url || r.name || 'Untitled') + '</a></div>' +
          '<div class="result-meta">' + escapeHtml(r.meta || '') + '</div>' +
          (r.url ? '<div class="result-url">' + escapeHtml(r.url) + '</div>' : '') +
          '</div>';
      }).join('');
    }

    function escapeHtml(s) {
      return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
  </script>
</body>
</html>`;
}

// ============================================================================
// Onboarding Status Type
// ============================================================================

interface OnboardingStatus {
  xConnected: boolean;
  githubConnected: boolean;
  extensionInstalled: boolean;
  mcpInstalled: boolean;
  subscribed: boolean;
  xUser: { username: string; name: string; profileImageUrl: string } | null;
  githubUser: { login: string; avatarUrl: string } | null;
  historyCount: number;
  bookmarkCount: number;
  repoCount: number;
}

// ============================================================================
// Durable Object: UserDO
// ============================================================================

export class UserDO extends DurableObject<Env> {
  private sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    this.initDatabase();
  }

  private initDatabase() {
    // ── KV store ──
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)`
    );

    // ── Registry table (only used by __registry__ DO) ──
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS user_registry (user_id TEXT PRIMARY KEY, username TEXT, name TEXT, profile_image_url TEXT, last_history_at INTEGER, last_mcp_at INTEGER, is_subscribed INTEGER DEFAULT 0, created_at INTEGER)`
    );
    // Migration: add columns if table existed before with fewer columns
    for (const col of [
      "username TEXT",
      "name TEXT",
      "profile_image_url TEXT",
      "last_history_at INTEGER",
      "last_mcp_at INTEGER",
      "is_subscribed INTEGER DEFAULT 0"
    ]) {
      try {
        this.sql.exec(`ALTER TABLE user_registry ADD COLUMN ${col}`);
      } catch (_) {}
    }

    // ── Browser history ──
    this.sql.exec(`CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL,
      title TEXT DEFAULT '',
      description TEXT DEFAULT '',
      duration INTEGER DEFAULT 0,
      timestamp INTEGER NOT NULL
    )`);
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_history_ts ON history(timestamp DESC)`
    );
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_history_url ON history(url)`);

    // ── X Bookmarks ──
    this.sql.exec(`CREATE TABLE IF NOT EXISTS bookmarks (
      id TEXT PRIMARY KEY,
      text TEXT,
      created_at TEXT,
      author_id TEXT,
      author_username TEXT DEFAULT '',
      public_metrics TEXT,
      synced_at INTEGER
    )`);
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_bookmarks_created ON bookmarks(created_at DESC)`
    );

    // ── GitHub Repos ──
    this.sql.exec(`CREATE TABLE IF NOT EXISTS repos (
      full_name TEXT PRIMARY KEY,
      description TEXT DEFAULT '',
      homepage TEXT DEFAULT '',
      stargazers_count INTEGER DEFAULT 0,
      language TEXT DEFAULT '',
      topics TEXT DEFAULT '',
      pushed_at TEXT,
      is_fork INTEGER DEFAULT 0,
      is_owner INTEGER DEFAULT 0,
      org_name TEXT DEFAULT '',
      is_starred INTEGER DEFAULT 0,
      synced_at INTEGER
    )`);
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_repos_pushed ON repos(pushed_at DESC)`
    );
  }

  // ── KV Helpers ──

  private kvGet(key: string): string | null {
    const rows = this.sql
      .exec("SELECT value FROM kv WHERE key = ?", key)
      .toArray();
    return rows.length > 0 ? (rows[0].value as string) : null;
  }

  private kvSet(key: string, value: string) {
    this.sql.exec(
      "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
      key,
      value
    );
  }

  private kvGetJson<T>(key: string): T | null {
    const v = this.kvGet(key);
    return v ? JSON.parse(v) : null;
  }

  private kvSetJson(key: string, value: any) {
    this.kvSet(key, JSON.stringify(value));
  }

  // ── Registry (only for __registry__ DO) ──

  async registerUser(data: {
    userId: string;
    username: string;
    name: string;
    profileImageUrl: string;
  }) {
    this.sql.exec(
      "INSERT INTO user_registry (user_id, username, name, profile_image_url, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET username=?, name=?, profile_image_url=?",
      data.userId,
      data.username,
      data.name,
      data.profileImageUrl,
      Date.now(),
      data.username,
      data.name,
      data.profileImageUrl
    );
  }

  async updateUserStats(
    userId: string,
    field: "last_history_at" | "last_mcp_at" | "is_subscribed",
    value: number
  ) {
    this.sql.exec(
      `UPDATE user_registry SET ${field} = ? WHERE user_id = ?`,
      value,
      userId
    );
  }

  async getAllUsers(): Promise<
    {
      user_id: string;
      username: string;
      name: string;
      profile_image_url: string;
      last_history_at: number | null;
      last_mcp_at: number | null;
      is_subscribed: number;
      created_at: number;
    }[]
  > {
    return this.sql
      .exec(
        "SELECT user_id, username, name, profile_image_url, last_history_at, last_mcp_at, is_subscribed, created_at FROM user_registry ORDER BY created_at DESC"
      )
      .toArray()
      .map((r) => ({
        user_id: r.user_id as string,
        username: (r.username || "") as string,
        name: (r.name || "") as string,
        profile_image_url: (r.profile_image_url || "") as string,
        last_history_at: r.last_history_at as number | null,
        last_mcp_at: r.last_mcp_at as number | null,
        is_subscribed: (r.is_subscribed || 0) as number,
        created_at: r.created_at as number
      }));
  }

  async getAllUserIds(): Promise<string[]> {
    return this.sql
      .exec("SELECT user_id FROM user_registry")
      .toArray()
      .map((r) => r.user_id as string);
  }

  // ── X Auth ──

  async setXAuth(data: {
    userId: string;
    username: string;
    name: string;
    profileImageUrl: string;
    accessToken: string;
    refreshToken?: string;
  }) {
    // make image bigger
    data.profileImageUrl = data.profileImageUrl.replace("_normal", "_400x400");
    this.kvSetJson("x_user", {
      username: data.username,
      name: data.name,
      profileImageUrl: data.profileImageUrl,
      userId: data.userId
    });
    this.kvSet("x_access_token", data.accessToken);
    if (data.refreshToken) this.kvSet("x_refresh_token", data.refreshToken);

    // Register in global registry
    const registryId = this.env.USER_DO.idFromName("__registry__");
    const registry = this.env.USER_DO.get(registryId);
    await registry.registerUser({
      userId: data.userId,
      username: data.username,
      name: data.name,
      profileImageUrl: data.profileImageUrl
    });
  }

  // ── GitHub Auth ──

  async setGitHubAuth(data: {
    login: string;
    id: number;
    avatarUrl: string;
    accessToken: string;
  }) {
    this.kvSetJson("gh_user", {
      login: data.login,
      id: data.id,
      avatarUrl: data.avatarUrl
    });
    this.kvSet("gh_access_token", data.accessToken);
  }

  // ── Subscription ──

  async activateSubscription(stripeCustomerId: string, subscriptionId: string) {
    this.kvSet("subscribed", "true");
    this.kvSet("stripe_customer_id", stripeCustomerId);
    this.kvSet("stripe_subscription_id", subscriptionId);
    this.kvSet("subscribed_at", String(Date.now()));

    // Start initial sync
    await this.syncAllData();

    // Set alarm for periodic sync (every hour)
    await this.ctx.storage.setAlarm(Date.now() + 60 * 60 * 1000);
  }

  async deactivateSubscription() {
    this.kvSet("subscribed", "false");
    await this.ctx.storage.deleteAlarm();
  }

  async isSubscriptionActive(): Promise<boolean> {
    return this.kvGet("subscribed") === "true";
  }

  // ── Alarm handler (periodic sync) ──

  async alarm() {
    if (await this.isSubscriptionActive()) {
      await this.syncAllData();
      // Reschedule
      await this.ctx.storage.setAlarm(Date.now() + 60 * 60 * 1000);
    }
  }

  // ── Mark onboarding step ──

  async markStep(step: string) {
    if (step === "extension") this.kvSet("extension_installed", "true");
    if (step === "mcp") this.kvSet("mcp_installed", "true");
  }

  // ── Onboarding status ──

  async getOnboardingStatus(): Promise<OnboardingStatus> {
    const xUser = this.kvGetJson<any>("x_user");
    const ghUser = this.kvGetJson<any>("gh_user");

    const historyCount =
      (this.sql.exec("SELECT COUNT(*) as c FROM history").toArray()[0]
        ?.c as number) || 0;
    const bookmarkCount =
      (this.sql.exec("SELECT COUNT(*) as c FROM bookmarks").toArray()[0]
        ?.c as number) || 0;
    const repoCount =
      (this.sql.exec("SELECT COUNT(*) as c FROM repos").toArray()[0]
        ?.c as number) || 0;

    return {
      xConnected: !!xUser,
      githubConnected: !!ghUser,
      extensionInstalled: this.kvGet("extension_installed") === "true",
      mcpInstalled: this.kvGet("mcp_installed") === "true",
      subscribed: this.kvGet("subscribed") === "true",
      xUser: xUser
        ? {
            username: xUser.username,
            name: xUser.name,
            profileImageUrl: xUser.profileImageUrl
          }
        : null,
      githubUser: ghUser
        ? { login: ghUser.login, avatarUrl: ghUser.avatarUrl }
        : null,
      historyCount,
      bookmarkCount,
      repoCount
    };
  }

  // ── Track visit ──

  async trackVisit(data: {
    url: string;
    title: string;
    description: string;
    duration: number;
    timestamp: number;
  }) {
    // Deduplicate: if the same URL was already visited today, add duration to existing row
    const dayStart = new Date(data.timestamp);
    dayStart.setUTCHours(0, 0, 0, 0);
    const dayEnd = dayStart.getTime() + 24 * 60 * 60 * 1000;

    const existing = this.sql
      .exec(
        "SELECT id, duration FROM history WHERE url = ? AND timestamp >= ? AND timestamp < ? LIMIT 1",
        data.url,
        dayStart.getTime(),
        dayEnd
      )
      .toArray();

    if (existing.length > 0) {
      this.sql.exec(
        "UPDATE history SET duration = duration + ?, title = ?, description = ?, timestamp = ? WHERE id = ?",
        data.duration,
        data.title,
        data.description,
        data.timestamp,
        existing[0].id
      );
    } else {
      this.sql.exec(
        "INSERT INTO history (url, title, description, duration, timestamp) VALUES (?, ?, ?, ?, ?)",
        data.url,
        data.title,
        data.description,
        data.duration,
        data.timestamp
      );
    }
  }

  // ── Search across all sources ──

  async search(
    query: string,
    from: string,
    until: string,
    source: string
  ): Promise<any[]> {
    const results: any[] = [];
    const fromTs = from ? new Date(from).getTime() : 0;
    const untilTs = until ? new Date(until + "T23:59:59Z").getTime() : Infinity;
    const trimmed = (query || "").trim();
    const hasQuery = trimmed.length > 0;

    // Split query into individual words for broader matching
    const words = trimmed.split(/\s+/).filter((w) => w.length > 0);
    const queries = hasQuery
      ? [trimmed, ...words.filter((w) => w !== trimmed)]
      : [];
    const seen = new Set<string>();

    if (source === "all" || source === "history") {
      if (hasQuery) {
        for (const q of queries) {
          const likeQuery = `%${q}%`;
          const historyRows = this.sql
            .exec(
              `SELECT url, title, description, duration, timestamp FROM history
             WHERE (title LIKE ? COLLATE NOCASE OR url LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE) AND timestamp >= ? AND timestamp <= ?
             ORDER BY timestamp DESC LIMIT 50`,
              likeQuery,
              likeQuery,
              likeQuery,
              fromTs,
              untilTs
            )
            .toArray();

          for (const row of historyRows) {
            const key = `history:${row.url}:${row.timestamp}`;
            if (seen.has(key)) continue;
            seen.add(key);
            results.push({
              source: "history",
              url: row.url,
              title: row.title || row.url,
              meta: `${Math.floor((row.duration as number) / 60)}m ${(row.duration as number) % 60}s — ${new Date(row.timestamp as number).toLocaleString()}`,
              timestamp: row.timestamp,
              duration: row.duration,
              description: row.description
            });
          }
        }
      } else {
        const historyRows = this.sql
          .exec(
            `SELECT url, title, description, duration, timestamp FROM history
           WHERE timestamp >= ? AND timestamp <= ?
           ORDER BY timestamp DESC LIMIT 50`,
            fromTs,
            untilTs
          )
          .toArray();

        for (const row of historyRows) {
          const key = `history:${row.url}:${row.timestamp}`;
          if (seen.has(key)) continue;
          seen.add(key);
          results.push({
            source: "history",
            url: row.url,
            title: row.title || row.url,
            meta: `${Math.floor((row.duration as number) / 60)}m ${(row.duration as number) % 60}s — ${new Date(row.timestamp as number).toLocaleString()}`,
            timestamp: row.timestamp,
            duration: row.duration,
            description: row.description
          });
        }
      }
    }

    if (source === "all" || source === "bookmarks") {
      if (hasQuery) {
        for (const q of queries) {
          const likeQuery = `%${q}%`;
          const bookmarkRows = this.sql
            .exec(
              `SELECT id, text, created_at, author_username FROM bookmarks
             WHERE text LIKE ? COLLATE NOCASE
             ORDER BY created_at DESC LIMIT 50`,
              likeQuery
            )
            .toArray();

          for (const row of bookmarkRows) {
            const createdAt = row.created_at
              ? new Date(row.created_at as string).getTime()
              : 0;
            if (createdAt >= fromTs && createdAt <= untilTs) {
              const key = `bookmarks:${row.id}`;
              if (seen.has(key)) continue;
              seen.add(key);
              results.push({
                source: "bookmarks",
                url: `https://x.com/i/status/${row.id}`,
                title: ((row.text as string) || "").slice(0, 120),
                meta: `@${row.author_username || "unknown"} — ${row.created_at}`,
                timestamp: createdAt,
                text: row.text
              });
            }
          }
        }
      } else {
        const bookmarkRows = this.sql
          .exec(
            `SELECT id, text, created_at, author_username FROM bookmarks
           ORDER BY created_at DESC LIMIT 50`
          )
          .toArray();

        for (const row of bookmarkRows) {
          const createdAt = row.created_at
            ? new Date(row.created_at as string).getTime()
            : 0;
          if (createdAt >= fromTs) {
            const key = `bookmarks:${row.id}`;
            if (seen.has(key)) continue;
            seen.add(key);
            results.push({
              source: "bookmarks",
              url: `https://x.com/i/status/${row.id}`,
              title: ((row.text as string) || "").slice(0, 120),
              meta: `@${row.author_username || "unknown"} — ${row.created_at}`,
              timestamp: createdAt,
              text: row.text
            });
          }
        }
      }
    }

    if (source === "all" || source === "repos") {
      if (hasQuery) {
        for (const q of queries) {
          const likeQuery = `%${q}%`;
          const repoRows = this.sql
            .exec(
              `SELECT full_name, description, homepage, stargazers_count, language, topics, pushed_at FROM repos
             WHERE (full_name LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE OR topics LIKE ? COLLATE NOCASE)
             ORDER BY pushed_at DESC LIMIT 50`,
              likeQuery,
              likeQuery,
              likeQuery
            )
            .toArray();

          for (const row of repoRows) {
            const pushedAt = row.pushed_at
              ? new Date(row.pushed_at as string).getTime()
              : 0;
            if (pushedAt >= fromTs && pushedAt <= untilTs) {
              const key = `repos:${row.full_name}`;
              if (seen.has(key)) continue;
              seen.add(key);
              results.push({
                source: "repos",
                url: `https://github.com/${row.full_name}`,
                title: row.full_name,
                name: row.full_name,
                meta: `⭐ ${row.stargazers_count} — ${row.language || ""} — ${row.description || ""}`,
                timestamp: pushedAt,
                description: row.description,
                stars: row.stargazers_count
              });
            }
          }
        }
      } else {
        const repoRows = this.sql
          .exec(
            `SELECT full_name, description, homepage, stargazers_count, language, topics, pushed_at FROM repos
           ORDER BY pushed_at DESC LIMIT 50`
          )
          .toArray();

        for (const row of repoRows) {
          const pushedAt = row.pushed_at
            ? new Date(row.pushed_at as string).getTime()
            : 0;
          if (pushedAt >= fromTs && pushedAt <= untilTs) {
            const key = `repos:${row.full_name}`;
            if (seen.has(key)) continue;
            seen.add(key);
            results.push({
              source: "repos",
              url: `https://github.com/${row.full_name}`,
              title: row.full_name,
              name: row.full_name,
              meta: `⭐ ${row.stargazers_count} — ${row.language || ""} — ${row.description || ""}`,
              timestamp: pushedAt,
              description: row.description,
              stars: row.stargazers_count
            });
          }
        }
      }
    }

    // Sort by timestamp descending
    results.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    return results.slice(0, 100);
  }

  // ── Daily summary ──

  async getDailySummary(date: string): Promise<any> {
    const dayStart = new Date(date + "T00:00:00Z").getTime();
    const dayEnd = dayStart + 24 * 60 * 60 * 1000;

    const history = this.sql
      .exec(
        `SELECT url, title, SUM(duration) as total_duration, COUNT(*) as visits
       FROM history WHERE timestamp >= ? AND timestamp < ?
       GROUP BY url ORDER BY total_duration DESC LIMIT 50`,
        dayStart,
        dayEnd
      )
      .toArray();

    return { date, history };
  }

  // ── Sync all data ──

  async syncAllData() {
    await this.syncBookmarks();
    await this.syncGitHubRepos();
  }

  // ── Sync X Bookmarks ──

  private async refreshXToken(): Promise<boolean> {
    const refreshToken = this.kvGet("x_refresh_token");
    if (!refreshToken) return false;

    const response = await fetch("https://api.x.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa(`${this.env.X_CLIENT_ID}:${this.env.X_CLIENT_SECRET}`)}`
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: this.env.X_CLIENT_ID
      })
    });

    if (!response.ok) return false;

    const tokens = (await response.json()) as XTokens;
    this.kvSet("x_access_token", tokens.access_token);
    if (tokens.refresh_token)
      this.kvSet("x_refresh_token", tokens.refresh_token);
    return true;
  }

  private async syncBookmarks() {
    const xUser = this.kvGetJson<any>("x_user");
    let accessToken = this.kvGet("x_access_token");
    if (!xUser || !accessToken) return;

    const userId = xUser.userId;
    const fetchUrl = new URL(`https://api.x.com/2/users/${userId}/bookmarks`);
    fetchUrl.searchParams.set("max_results", "100");
    fetchUrl.searchParams.set(
      "tweet.fields",
      "created_at,author_id,public_metrics"
    );
    fetchUrl.searchParams.set("expansions", "author_id");
    fetchUrl.searchParams.set("user.fields", "username");

    let response = await fetch(fetchUrl.toString(), {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    // Handle expired token
    if (response.status === 401) {
      const refreshed = await this.refreshXToken();
      if (!refreshed) return;
      accessToken = this.kvGet("x_access_token");
      response = await fetch(fetchUrl.toString(), {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
    }

    if (response.status === 429 || !response.ok) {
      console.log("Bookmark sync issue:", response.status);
      return;
    }

    const data = (await response.json()) as any;
    if (!data.data) return;

    // Build author map
    const authorMap: Record<string, string> = {};
    if (data.includes?.users) {
      for (const u of data.includes.users) {
        authorMap[u.id] = u.username;
      }
    }

    for (const bookmark of data.data) {
      this.sql.exec(
        `INSERT OR REPLACE INTO bookmarks (id, text, created_at, author_id, author_username, public_metrics, synced_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        bookmark.id,
        bookmark.text,
        bookmark.created_at,
        bookmark.author_id,
        authorMap[bookmark.author_id] || "",
        JSON.stringify(bookmark.public_metrics || {}),
        Date.now()
      );
    }
  }

  // ── Sync GitHub Repos ──

  private async syncGitHubRepos() {
    const ghUser = this.kvGetJson<any>("gh_user");
    const accessToken = this.kvGet("gh_access_token");
    if (!ghUser || !accessToken) return;

    const headers = {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "ProMind/1.0"
    };

    // Fetch own repos
    let page = 1;
    while (true) {
      const res = await fetch(
        `https://api.github.com/user/repos?per_page=100&page=${page}&affiliation=owner,organization_member&sort=pushed`,
        { headers }
      );
      if (!res.ok) break;
      const repos = (await res.json()) as any[];
      if (!repos.length) break;

      for (const repo of repos) {
        this.sql.exec(
          `INSERT OR REPLACE INTO repos (full_name, description, homepage, stargazers_count, language, topics, pushed_at, is_fork, is_owner, org_name, is_starred, synced_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT is_starred FROM repos WHERE full_name = ?), 0), ?)`,
          repo.full_name,
          repo.description || "",
          repo.homepage || "",
          repo.stargazers_count || 0,
          repo.language || "",
          (repo.topics || []).join(","),
          repo.pushed_at || "",
          repo.fork ? 1 : 0,
          repo.owner.login === ghUser.login ? 1 : 0,
          repo.owner.type === "Organization" ? repo.owner.login : "",
          repo.full_name,
          Date.now()
        );
      }

      if (repos.length < 100) break;
      page++;
    }

    // Fetch starred repos
    page = 1;
    while (true) {
      const res = await fetch(
        `https://api.github.com/user/starred?per_page=100&page=${page}`,
        { headers }
      );
      if (!res.ok) break;
      const repos = (await res.json()) as any[];
      if (!repos.length) break;

      for (const repo of repos) {
        this.sql.exec(
          `INSERT INTO repos (full_name, description, homepage, stargazers_count, language, topics, pushed_at, is_fork, is_owner, org_name, is_starred, synced_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 1, ?)
           ON CONFLICT(full_name) DO UPDATE SET
             description = excluded.description,
             stargazers_count = excluded.stargazers_count,
             is_starred = 1,
             synced_at = excluded.synced_at`,
          repo.full_name,
          repo.description || "",
          repo.homepage || "",
          repo.stargazers_count || 0,
          repo.language || "",
          (repo.topics || []).join(","),
          repo.pushed_at || "",
          repo.fork ? 1 : 0,
          repo.owner.type === "Organization" ? repo.owner.login : "",
          Date.now()
        );
      }

      if (repos.length < 100) break;
      page++;
    }
  }
}
