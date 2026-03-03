/**
 * X OAuth Worker for Browser Extension with Server-Side Storage
 *
 * This worker handles X OAuth 2.0 with PKCE, JWT-based authentication,
 * and stores tracking data in SQLite Durable Objects.
 */

interface Env {
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  JWT_SECRET: string;
  PARALLEL_API_KEY: string;
  USER_STATS: DurableObjectNamespace;
  ADMIN_STATS: DurableObjectNamespace;
}

// The extension will listen for redirects to this URL pattern
const EXTENSION_CALLBACK_PATH = "/extension-callback";

// ===== JWT Utilities =====

interface JWTPayload {
  sub: string;
  username: string;
  name: string;
  pfp: string;
  iat: number;
}

async function createJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };

  const encodedHeader = btoa(JSON.stringify(header))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const encodedPayload = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const data = `${encodedHeader}.${encodedPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  const encodedSignature = btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return `${data}.${encodedSignature}`;
}

async function verifyJWT(
  token: string,
  secret: string
): Promise<JWTPayload | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const data = `${encodedHeader}.${encodedPayload}`;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    // Decode signature from base64url
    const signatureStr = atob(
      encodedSignature.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - (encodedSignature.length % 4)) % 4)
    );
    const signature = new Uint8Array(signatureStr.length);
    for (let i = 0; i < signatureStr.length; i++) {
      signature[i] = signatureStr.charCodeAt(i);
    }

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(data)
    );

    if (!valid) return null;

    // Decode payload
    const payloadStr = atob(
      encodedPayload.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - (encodedPayload.length % 4)) % 4)
    );

    return JSON.parse(payloadStr) as JWTPayload;
  } catch {
    return null;
  }
}

// ===== UserStats Durable Object =====

interface VisitRow {
  domain: string;
  total_time: number;
  visit_count: number;
  last_visit: string;
}

interface IndividualVisit {
  id: number;
  domain: string;
  duration_seconds: number;
  visited_at: string;
  title: string;
  description: string;
}

export class UserStats implements DurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
    this.initializeSchema();
  }

  private initializeSchema() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        duration_seconds INTEGER NOT NULL,
        visited_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_domain ON visits(domain);
    `);

    // Migrate: add title and description columns
    try {
      this.sql.exec(
        `ALTER TABLE visits ADD COLUMN title TEXT NOT NULL DEFAULT ''`
      );
    } catch {}
    try {
      this.sql.exec(
        `ALTER TABLE visits ADD COLUMN description TEXT NOT NULL DEFAULT ''`
      );
    } catch {}
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/track" && request.method === "POST") {
      return this.handleTrack(request);
    }

    if (url.pathname === "/stats" && request.method === "GET") {
      return this.handleStats();
    }

    if (url.pathname === "/visits" && request.method === "GET") {
      return this.handleVisits();
    }

    if (url.pathname === "/search" && request.method === "POST") {
      return this.handleSearch(request);
    }

    return new Response("Not found", { status: 404 });
  }

  private async handleTrack(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as {
        domain: string;
        duration: number;
        title?: string;
        description?: string;
      };

      const { domain, duration, title, description } = body;

      if (!domain || typeof duration !== "number" || duration <= 0) {
        return new Response(
          JSON.stringify({ error: "Invalid domain or duration" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      const visitedAt = new Date().toISOString();

      this.sql.exec(
        `INSERT INTO visits (domain, duration_seconds, visited_at, title, description) VALUES (?, ?, ?, ?, ?)`,
        domain,
        duration,
        visitedAt,
        title || "",
        description || ""
      );

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "Failed to track visit",
          details: error instanceof Error ? error.message : "Unknown error"
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  private async handleStats(): Promise<Response> {
    try {
      // Get aggregated stats by domain
      const rows = this.sql
        .exec(
          `
        SELECT
          domain,
          SUM(duration_seconds) as total_time,
          COUNT(*) as visit_count,
          MAX(visited_at) as last_visit
        FROM visits
        GROUP BY domain
        ORDER BY total_time DESC
      `
        )
        .toArray() as unknown as VisitRow[];

      const stats = rows.map((row: VisitRow) => ({
        domain: row.domain,
        totalTime: row.total_time,
        visitCount: row.visit_count,
        lastVisit: row.last_visit
      }));

      return new Response(JSON.stringify({ stats }), {
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "Failed to get stats",
          details: error instanceof Error ? error.message : "Unknown error"
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  private async handleVisits(): Promise<Response> {
    try {
      // Get individual visits ordered reverse chronologically
      const rows = this.sql
        .exec(
          `
        SELECT
          id,
          domain,
          duration_seconds,
          visited_at,
          title,
          description
        FROM visits
        ORDER BY visited_at DESC
        LIMIT 1000
      `
        )
        .toArray() as unknown as IndividualVisit[];

      const visits = rows.map((row: IndividualVisit) => ({
        id: row.id,
        url: row.domain,
        duration: row.duration_seconds,
        visitedAt: row.visited_at,
        title: row.title,
        description: row.description
      }));

      return new Response(JSON.stringify({ visits }), {
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "Failed to get visits",
          details: error instanceof Error ? error.message : "Unknown error"
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  private async handleSearch(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as {
        from?: string;
        to?: string;
        query?: string;
      };

      // Accept YYYY-MM-DD or full ISO strings
      const normalizeDate = (
        d: string | undefined,
        fallback: string,
        endOfDay: boolean
      ) => {
        if (!d) return fallback;
        if (/^\d{4}-\d{2}-\d{2}$/.test(d))
          return endOfDay ? `${d}T23:59:59.999Z` : `${d}T00:00:00.000Z`;
        return d;
      };
      const from = normalizeDate(body.from, "1970-01-01T00:00:00.000Z", false);
      const to = normalizeDate(body.to, new Date().toISOString(), true);
      const query = body.query || "";

      let rows: IndividualVisit[];
      if (query) {
        const like = `%${query}%`;
        rows = this.sql
          .exec(
            `SELECT id, domain, duration_seconds, visited_at, title, description
             FROM visits
             WHERE visited_at >= ? AND visited_at <= ?
               AND (domain LIKE ? OR title LIKE ? OR description LIKE ?)
             ORDER BY visited_at ASC`,
            from,
            to,
            like,
            like,
            like
          )
          .toArray() as unknown as IndividualVisit[];
      } else {
        rows = this.sql
          .exec(
            `SELECT id, domain, duration_seconds, visited_at, title, description
             FROM visits
             WHERE visited_at >= ? AND visited_at <= ?
             ORDER BY visited_at ASC`,
            from,
            to
          )
          .toArray() as unknown as IndividualVisit[];
      }

      const visits = rows.map((row) => ({
        id: row.id,
        url: row.domain,
        duration: row.duration_seconds,
        visitedAt: row.visited_at,
        title: row.title,
        description: row.description
      }));

      return new Response(JSON.stringify({ visits }), {
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "Failed to search visits",
          details: error instanceof Error ? error.message : "Unknown error"
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }
}

// ===== AdminStats Durable Object =====

interface AdminUserRow {
  sub: string;
  username: string;
  name: string;
  pfp: string;
  iat: number;
  active_at: string;
  track_count: number;
  mcp_tool_call_count: number;
  mcp_active_at: string;
}

export class AdminStats implements DurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
    this.initializeSchema();
  }

  private initializeSchema() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        sub TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        name TEXT NOT NULL,
        pfp TEXT NOT NULL DEFAULT '',
        iat INTEGER NOT NULL,
        active_at TEXT NOT NULL,
        track_count INTEGER NOT NULL DEFAULT 0,
        mcp_tool_call_count INTEGER NOT NULL DEFAULT 0,
        mcp_active_at TEXT NOT NULL DEFAULT ''
      );
    `);

    // Migrate: add mcp columns
    try {
      this.sql.exec(
        `ALTER TABLE users ADD COLUMN mcp_tool_call_count INTEGER NOT NULL DEFAULT 0`
      );
    } catch {}
    try {
      this.sql.exec(
        `ALTER TABLE users ADD COLUMN mcp_active_at TEXT NOT NULL DEFAULT ''`
      );
    } catch {}
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/upsert-user" && request.method === "POST") {
      return this.handleUpsertUser(request);
    }

    if (url.pathname === "/track-activity" && request.method === "POST") {
      return this.handleTrackActivity(request);
    }

    if (url.pathname === "/mcp-activity" && request.method === "POST") {
      return this.handleMcpActivity(request);
    }

    if (url.pathname === "/users" && request.method === "GET") {
      return this.handleGetUsers();
    }

    return new Response("Not found", { status: 404 });
  }

  private async handleUpsertUser(request: Request): Promise<Response> {
    const body = (await request.json()) as {
      sub: string;
      username: string;
      name: string;
      pfp: string;
      iat: number;
    };

    const now = new Date().toISOString();

    // Check if user exists
    const existing = this.sql
      .exec(`SELECT track_count FROM users WHERE sub = ?`, body.sub)
      .toArray();

    if (existing.length > 0) {
      this.sql.exec(
        `UPDATE users SET username = ?, name = ?, pfp = ?, iat = ?, active_at = ? WHERE sub = ?`,
        body.username,
        body.name,
        body.pfp,
        body.iat,
        now,
        body.sub
      );
    } else {
      this.sql.exec(
        `INSERT INTO users (sub, username, name, pfp, iat, active_at, track_count) VALUES (?, ?, ?, ?, ?, ?, 0)`,
        body.sub,
        body.username,
        body.name,
        body.pfp,
        body.iat,
        now
      );
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  private async handleTrackActivity(request: Request): Promise<Response> {
    const body = (await request.json()) as { sub: string };
    const now = new Date().toISOString();

    this.sql.exec(
      `UPDATE users SET active_at = ?, track_count = track_count + 1 WHERE sub = ?`,
      now,
      body.sub
    );

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  private async handleMcpActivity(request: Request): Promise<Response> {
    const body = (await request.json()) as { sub: string };
    const now = new Date().toISOString();

    this.sql.exec(
      `UPDATE users SET mcp_active_at = ?, mcp_tool_call_count = mcp_tool_call_count + 1 WHERE sub = ?`,
      now,
      body.sub
    );

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  private async handleGetUsers(): Promise<Response> {
    const rows = this.sql
      .exec(
        `SELECT sub, username, name, pfp, iat, active_at, track_count, mcp_tool_call_count, mcp_active_at FROM users ORDER BY active_at DESC`
      )
      .toArray() as unknown as AdminUserRow[];

    return new Response(JSON.stringify({ users: rows }), {
      headers: { "Content-Type": "application/json" },
    });
  }
}

// ===== Helper Functions =====

async function generateRandomString(length: number): Promise<string> {
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function getCookie(
  cookieHeader: string | null,
  name: string
): string | undefined {
  if (!cookieHeader) return undefined;
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  const cookie = cookies.find((c) => c.startsWith(`${name}=`));
  return cookie?.split("=")[1];
}

function formatTime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  } else {
    return `${secs}s`;
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function extractHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

// ===== MCP Middleware =====

interface McpAuthCode {
  sub: string;
  username: string;
  name: string;
  pfp: string;
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
  name: string;
  pfp: string;
  scope: string;
  type: "mcp_access";
  iat: number;
}

async function mcpMiddleware(
  request: Request,
  env: Env
): Promise<Response | null> {
  const url = new URL(request.url);
  const origin = url.origin;

  // GET /.well-known/oauth-protected-resource
  if (url.pathname === "/.well-known/oauth-protected-resource") {
    return new Response(
      JSON.stringify({
        resource: origin,
        authorization_servers: [origin],
        scopes_supported: ["history:read", "fetch:read"],
        bearer_methods_supported: ["header"]
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  // GET /.well-known/oauth-authorization-server
  if (url.pathname === "/.well-known/oauth-authorization-server") {
    return new Response(
      JSON.stringify({
        issuer: origin,
        authorization_endpoint: `${origin}/mcp/authorize`,
        token_endpoint: `${origin}/mcp/token`,
        registration_endpoint: `${origin}/mcp/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["history:read", "fetch:read"],
        client_id_metadata_document_supported: true
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  // POST /mcp/register - Dynamic client registration (accepts any client)
  if (url.pathname === "/mcp/register" && request.method === "POST") {
    const body = (await request.json()) as {
      client_name?: string;
      redirect_uris?: string[];
      grant_types?: string[];
      response_types?: string[];
      token_endpoint_auth_method?: string;
    };

    const clientId = `client_${crypto.randomUUID()}`;

    return new Response(
      JSON.stringify({
        client_id: clientId,
        client_name: body.client_name || "MCP Client",
        redirect_uris: body.redirect_uris || [],
        grant_types: body.grant_types || ["authorization_code"],
        response_types: body.response_types || ["code"],
        token_endpoint_auth_method: body.token_endpoint_auth_method || "none"
      }),
      {
        status: 201,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // GET /mcp/authorize - Authorization endpoint
  if (url.pathname === "/mcp/authorize" && request.method === "GET") {
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
      return new Response(
        JSON.stringify({
          error: "invalid_request",
          error_description:
            "Missing required parameters: response_type=code, client_id, redirect_uri, code_challenge"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    if (codeChallengeMethod && codeChallengeMethod !== "S256") {
      return new Response(
        JSON.stringify({
          error: "invalid_request",
          error_description: "Only S256 code_challenge_method is supported"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Check for existing JWT session (from X OAuth login)
    const cookieHeader = request.headers.get("Cookie");
    const jwtCookie = getCookie(cookieHeader, "jwt");
    const payload = jwtCookie
      ? await verifyJWT(jwtCookie, env.JWT_SECRET)
      : null;

    if (!payload) {
      // Show login page - user needs to authenticate via X first
      const returnUrl = url.toString();
      const html = `<!DOCTYPE html>
<html>
<head>
  <title>MCP Authorization</title>
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="shortcut icon" href="/favicon.ico" />
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
<link rel="manifest" href="/site.webmanifest" />
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
    .container { text-align: center; padding: 40px; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; }
    h1 { margin: 0 0 8px 0; color: #333; font-size: 20px; }
    p { color: #666; margin: 0 0 20px 0; font-size: 14px; }
    a.btn { display: inline-block; padding: 12px 24px; background: #1da1f2; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; }
    a.btn:hover { background: #0d8ecf; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Sign in required</h1>
    <p>An MCP client wants to access your browsing history. Please sign in with X first, then return to this page.</p>
    <a class="btn" href="/login">Sign in with X</a>
  </div>
</body>
</html>`;
      return new Response(html, {
        status: 200,
        headers: { "Content-Type": "text/html;charset=utf8" }
      });
    }

    // User is authenticated - issue auth code as a signed JWT
    const authCode: McpAuthCode = {
      sub: payload.sub,
      username: payload.username,
      name: payload.name,
      pfp: payload.pfp,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      scope,
      type: "mcp_auth_code",
      exp: Math.floor(Date.now() / 1000) + 300 // 5 minutes
    };

    const code = await createJWT(
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

  // POST /mcp/token - Token endpoint
  if (url.pathname === "/mcp/token" && request.method === "POST") {
    let params: URLSearchParams;
    const contentType = request.headers.get("Content-Type") || "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      params = new URLSearchParams(await request.text());
    } else if (contentType.includes("application/json")) {
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
      return new Response(
        JSON.stringify({
          error: "invalid_request",
          error_description:
            "Missing required parameters: grant_type=authorization_code, code, code_verifier"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Decode the auth code JWT
    const authCode = (await verifyJWT(
      code,
      env.JWT_SECRET
    )) as unknown as McpAuthCode | null;

    if (!authCode || authCode.type !== "mcp_auth_code") {
      return new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "Invalid or expired authorization code"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Check expiration
    if (authCode.exp < Math.floor(Date.now() / 1000)) {
      return new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "Authorization code has expired"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Validate client_id and redirect_uri
    if (clientId && clientId !== authCode.client_id) {
      return new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "client_id mismatch"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    if (redirectUri && redirectUri !== authCode.redirect_uri) {
      return new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "redirect_uri mismatch"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Verify PKCE: S256 code_challenge = BASE64URL(SHA256(code_verifier))
    const challengeFromVerifier = await generateCodeChallenge(codeVerifier);
    if (challengeFromVerifier !== authCode.code_challenge) {
      return new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "PKCE verification failed"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Issue access token
    const accessToken: McpAccessToken = {
      sub: authCode.sub,
      username: authCode.username,
      name: authCode.name,
      pfp: authCode.pfp,
      scope: authCode.scope,
      type: "mcp_access",
      iat: Math.floor(Date.now() / 1000)
    };

    const token = await createJWT(
      accessToken as unknown as JWTPayload,
      env.JWT_SECRET
    );

    return new Response(
      JSON.stringify({
        access_token: token,
        token_type: "bearer",
        scope: authCode.scope
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  // MCP endpoint
  if (url.pathname === "/mcp") {
    // Handle OPTIONS for CORS
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

    const mcpCorsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Expose-Headers": "Mcp-Session-Id"
    };

    // Validate Bearer token
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
    const accessToken = (await verifyJWT(
      tokenStr,
      env.JWT_SECRET
    )) as unknown as McpAccessToken | null;

    if (!accessToken || accessToken.type !== "mcp_access") {
      return new Response("", {
        status: 401,
        headers: {
          "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
          ...mcpCorsHeaders
        }
      });
    }

    // GET /mcp - SSE endpoint (return method not allowed for now, we only support POST)
    if (request.method === "GET") {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32600, message: "Use POST for MCP requests" }
        }),
        {
          status: 405,
          headers: {
            "Content-Type": "application/json",
            ...mcpCorsHeaders
          }
        }
      );
    }

    // DELETE /mcp - Session termination
    if (request.method === "DELETE") {
      return new Response(null, {
        status: 200,
        headers: mcpCorsHeaders
      });
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
        new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), {
          headers: {
            "Content-Type": "application/json",
            "Mcp-Session-Id": sessionId,
            ...mcpCorsHeaders
          }
        });

      const respondError = (code: number, message: string) =>
        new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: body.id,
            error: { code, message }
          }),
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
            serverInfo: {
              name: "browser-history",
              version: "1.0.0"
            }
          });

        case "notifications/initialized":
          return new Response(null, {
            status: 204,
            headers: {
              "Mcp-Session-Id": sessionId,
              ...mcpCorsHeaders
            }
          });

        case "tools/list": {
          const today = new Date().toISOString().split("T")[0];
          return respond({
            tools: [
              {
                name: "search",
                description: `Search your browsing history by date range and/or query text. Returns matching visits in chronological order with URL, title, description, duration, and timestamp. Today's date is ${today}.`,
                inputSchema: {
                  type: "object",
                  properties: {
                    from: {
                      type: "string",
                      description:
                        "Start date in YYYY-MM-DD format (e.g. 2025-01-01). Defaults to all time."
                    },
                    to: {
                      type: "string",
                      description: `End date in YYYY-MM-DD format (e.g. ${today}). Defaults to today.`
                    },
                    query: {
                      type: "string",
                      description:
                        "Text to search for in URLs, page titles, and descriptions."
                    }
                  }
                }
              },
              {
                name: "fetch",
                description:
                  "Fetch and extract the content of a URL as clean markdown using the Parallel Extract API.",
                inputSchema: {
                  type: "object",
                  properties: {
                    url: {
                      type: "string",
                      description: "The URL to fetch and extract content from."
                    }
                  },
                  required: ["url"]
                }
              }
            ]
          });
        }

        case "tools/call": {
          // Track MCP tool call in admin stats
          try {
            const adminId = env.ADMIN_STATS.idFromName("global");
            const adminStub = env.ADMIN_STATS.get(adminId);
            adminStub.fetch(
              new Request("https://do/mcp-activity", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sub: accessToken.sub }),
              })
            );
          } catch (e) {
            console.error("Failed to update admin mcp stats:", e);
          }

          const toolName = (body.params as { name: string })?.name;
          const toolArgs =
            (body.params as { arguments?: Record<string, unknown> })
              ?.arguments || {};

          if (toolName === "search") {
            const doId = env.USER_STATS.idFromName(accessToken.sub);
            const stub = env.USER_STATS.get(doId);

            const searchResponse = await stub.fetch(
              new Request("https://do/search", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  from: toolArgs.from,
                  to: toolArgs.to,
                  query: toolArgs.query
                })
              })
            );

            const searchData = (await searchResponse.json()) as {
              visits: Array<{
                id: number;
                url: string;
                duration: number;
                visitedAt: string;
                title: string;
                description: string;
              }>;
            };

            return respond({
              content: [
                {
                  type: "text",
                  text: JSON.stringify(searchData.visits, null, 2)
                }
              ]
            });
          }

          if (toolName === "fetch") {
            const fetchUrl = toolArgs.url as string;
            if (!fetchUrl) {
              return respondError(-32602, "Missing required parameter: url");
            }

            try {
              const extractResponse = await fetch(
                "https://api.parallel.ai/v1beta/extract",
                {
                  method: "POST",
                  headers: {
                    "Content-Type": "application/json",
                    "x-api-key": env.PARALLEL_API_KEY,
                    "parallel-beta": "search-extract-2025-10-10"
                  },
                  body: JSON.stringify({
                    urls: [fetchUrl],
                    objective: "Extract the full content of this page",
                    excerpts: false,
                    full_content: true
                  })
                }
              );

              if (!extractResponse.ok) {
                const errText = await extractResponse.text();
                return respond({
                  content: [
                    {
                      type: "text",
                      text: `Failed to extract content (${extractResponse.status}): ${errText}`
                    }
                  ],
                  isError: true
                });
              }

              const extractData = (await extractResponse.json()) as {
                results?: Array<{
                  url: string;
                  title?: string;
                  publish_date?: string;
                  full_content?: string;
                  excerpts?: string;
                }>;
              };

              const result = extractData.results?.[0];
              const content = result?.full_content || "No content extracted.";
              const title = result?.title || fetchUrl;

              return respond({
                content: [
                  {
                    type: "text",
                    text: `# ${title}\n\n${content}`
                  }
                ]
              });
            } catch (error) {
              return respond({
                content: [
                  {
                    type: "text",
                    text: `Error fetching URL: ${error instanceof Error ? error.message : "Unknown error"}`
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

  return null;
}

// ===== Main Worker =====

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const isLocalhost = url.hostname === "localhost";
    const securePart = isLocalhost ? "" : "Secure; ";
    const redirectUri = `https://redirect.simplerauth.com/callback?redirect_to=${encodeURIComponent(url.origin + `/callback`)}`;

    // Validate environment
    if (!env.X_CLIENT_ID || !env.X_CLIENT_SECRET) {
      return new Response(
        JSON.stringify({
          error: "Server misconfigured: missing X credentials"
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }

    // CORS headers for extension
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // MCP middleware - handles /mcp, /.well-known/oauth-*, /mcp/*
    const mcpResponse = await mcpMiddleware(request, env);
    if (mcpResponse) return mcpResponse;

    // GET /login - Start OAuth flow
    if (url.pathname === "/login") {
      const scope =
        url.searchParams.get("scope") || "users.read tweet.read offline.access";

      const state = await generateRandomString(16);
      const codeVerifier = await generateRandomString(43);
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const authUrl = new URL("https://x.com/i/oauth2/authorize");
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", env.X_CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", scope);
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      const headers = new Headers({
        Location: authUrl.toString()
      });

      // Store state and verifier in cookies for callback validation
      headers.append(
        "Set-Cookie",
        `x_oauth_state=${state}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=600`
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=600`
      );
      headers.append(
        "Set-Cookie",
        `x_redirect_uri=${encodeURIComponent(redirectUri)}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=600`
      );

      // Store login source so callback knows where to redirect
      const source = url.searchParams.get("source") || "";
      if (source) {
        headers.append(
          "Set-Cookie",
          `x_login_source=${source}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=600`
        );
      }

      return new Response("Redirecting to X...", { status: 307, headers });
    }

    // GET /callback - X OAuth callback
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      const urlState = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        return redirectToExtension(url.origin, {
          error,
          error_description:
            url.searchParams.get("error_description") || "Authorization denied"
        });
      }

      const cookieHeader = request.headers.get("Cookie");
      const stateCookie = getCookie(cookieHeader, "x_oauth_state");
      const codeVerifier = getCookie(cookieHeader, "x_code_verifier");
      const finalRedirectUri = decodeURIComponent(
        getCookie(cookieHeader, "x_redirect_uri") || redirectUri
      );

      // Validate state
      if (
        !urlState ||
        !stateCookie ||
        urlState !== stateCookie ||
        !codeVerifier
      ) {
        return redirectToExtension(url.origin, {
          error: "invalid_state",
          error_description: "Invalid or expired state. Please try again."
        });
      }

      try {
        // Exchange code for tokens
        const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${btoa(`${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`)}`
          },
          body: new URLSearchParams({
            code: code || "",
            client_id: env.X_CLIENT_ID,
            grant_type: "authorization_code",
            redirect_uri: finalRedirectUri,
            code_verifier: codeVerifier
          })
        });

        const tokenText = await tokenResponse.text();

        if (!tokenResponse.ok) {
          console.error(
            "Token exchange failed:",
            tokenResponse.status,
            tokenText
          );
          return redirectToExtension(url.origin, {
            error: "token_exchange_failed",
            error_description: `Failed to exchange token: ${tokenResponse.status}`
          });
        }

        const tokenData = JSON.parse(tokenText);
        const { access_token, refresh_token } = tokenData;

        // Fetch user info
        interface XUser {
          id: string;
          username: string;
          name: string;
          profile_image_url?: string;
        }
        let user: XUser | null = null;
        try {
          const userResponse = await fetch(
            "https://api.x.com/2/users/me?user.fields=profile_image_url,username,name",
            { headers: { Authorization: `Bearer ${access_token}` } }
          );
          if (userResponse.ok) {
            const userData = (await userResponse.json()) as { data: XUser };
            user = userData.data;
          }
        } catch (e) {
          console.error("Failed to fetch user info:", e);
        }

        if (!user) {
          return redirectToExtension(url.origin, {
            error: "user_fetch_failed",
            error_description: "Failed to fetch user information"
          });
        }

        // Create JWT token
        const jwtPayload: JWTPayload = {
          sub: user.id,
          username: user.username,
          name: user.name,
          pfp: user.profile_image_url?.replace("_normal", "_400x400") || "",
          iat: Math.floor(Date.now() / 1000)
        };

        const jwt = await createJWT(jwtPayload, env.JWT_SECRET);

        // Register/update user in AdminStats
        try {
          const adminId = env.ADMIN_STATS.idFromName("global");
          const adminStub = env.ADMIN_STATS.get(adminId);
          await adminStub.fetch(
            new Request("https://do/upsert-user", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                sub: user.id,
                username: user.username,
                name: user.name,
                pfp: jwtPayload.pfp,
                iat: jwtPayload.iat,
              }),
            })
          );
        } catch (e) {
          console.error("Failed to update admin stats:", e);
        }

        // Check if login originated from the website
        const loginSource = getCookie(cookieHeader, "x_login_source");
        if (loginSource === "web") {
          const headers = new Headers({ Location: "/" });
          headers.append(
            "Set-Cookie",
            `jwt=${jwt}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=${60 * 60 * 24 * 365}`
          );
          headers.append("Set-Cookie", "x_login_source=; Max-Age=0; Path=/");
          headers.append("Set-Cookie", "x_oauth_state=; Max-Age=0; Path=/");
          headers.append("Set-Cookie", "x_code_verifier=; Max-Age=0; Path=/");
          headers.append("Set-Cookie", "x_redirect_uri=; Max-Age=0; Path=/");
          return new Response("Redirecting...", { status: 302, headers });
        }

        // Redirect to extension callback with JWT
        return redirectToExtension(url.origin, {
          jwt,
          refresh_token,
          user: JSON.stringify(user)
        });
      } catch (error) {
        console.error("OAuth callback error:", error);
        return redirectToExtension(url.origin, {
          error: "server_error",
          error_description:
            error instanceof Error ? error.message : "Unknown error"
        });
      }
    }

    // GET /extension-callback - Landing page the extension intercepts
    if (url.pathname === EXTENSION_CALLBACK_PATH) {
      const jwt = url.searchParams.get("jwt");
      const error = url.searchParams.get("error");

      const html = `<!DOCTYPE html>
<html>
<head>
  <title>${error ? "Login Failed" : "Login Successful"}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .icon { font-size: 48px; margin-bottom: 16px; }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">${error ? "X" : "OK"}</div>
    <h1>${error ? "Login Failed" : "Login Successful"}</h1>
    <p>${error ? url.searchParams.get("error_description") || error : "You can close this tab now."}</p>
  </div>
</body>
</html>`;

      return new Response(html, {
        headers: {
          "Content-Type": "text/html;charset=utf8",
          ...corsHeaders
        }
      });
    }

    // POST /api/track - Record a visit (requires JWT)
    if (url.pathname === "/api/track" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response(
          JSON.stringify({ error: "Missing or invalid authorization header" }),
          {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders }
          }
        );
      }

      const token = authHeader.slice(7);
      const payload = await verifyJWT(token, env.JWT_SECRET);

      if (!payload) {
        return new Response(
          JSON.stringify({ error: "Invalid or expired token" }),
          {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders }
          }
        );
      }

      // Get user's Durable Object
      const id = env.USER_STATS.idFromName(payload.sub);
      const stub = env.USER_STATS.get(id);

      // Forward request to Durable Object
      const doRequest = new Request("https://do/track", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: request.body
      });

      const response = await stub.fetch(doRequest);
      const responseBody = await response.text();

      // Update admin stats (track activity)
      try {
        const adminId = env.ADMIN_STATS.idFromName("global");
        const adminStub = env.ADMIN_STATS.get(adminId);
        await adminStub.fetch(
          new Request("https://do/track-activity", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sub: payload.sub }),
          })
        );
      } catch (e) {
        console.error("Failed to update admin track stats:", e);
      }

      return new Response(responseBody, {
        status: response.status,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    // GET /api/stats - Get stats as JSON (requires JWT)
    if (url.pathname === "/api/stats" && request.method === "GET") {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response(
          JSON.stringify({ error: "Missing or invalid authorization header" }),
          {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders }
          }
        );
      }

      const token = authHeader.slice(7);
      const payload = await verifyJWT(token, env.JWT_SECRET);

      if (!payload) {
        return new Response(
          JSON.stringify({ error: "Invalid or expired token" }),
          {
            status: 401,
            headers: { "Content-Type": "application/json", ...corsHeaders }
          }
        );
      }

      // Get user's Durable Object
      const id = env.USER_STATS.idFromName(payload.sub);
      const stub = env.USER_STATS.get(id);

      const response = await stub.fetch(new Request("https://do/stats"));
      const responseBody = await response.text();

      return new Response(responseBody, {
        status: response.status,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    // GET /stats - HTML stats page (JWT from query param or cookie)
    if (url.pathname === "/stats") {
      const tokenFromQuery = url.searchParams.get("token");
      const tokenFromCookie = getCookie(request.headers.get("Cookie"), "jwt");
      const token = tokenFromQuery || tokenFromCookie;

      if (!token) {
        return new Response(
          `<!DOCTYPE html>
<html>
<head>
  <title>Not Authorized</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Not Authorized</h1>
    <p>Please login from the browser extension to view your stats.</p>
  </div>
</body>
</html>`,
          { status: 401, headers: { "Content-Type": "text/html;charset=utf8" } }
        );
      }

      const payload = await verifyJWT(token, env.JWT_SECRET);

      if (!payload) {
        return new Response(
          `<!DOCTYPE html>
<html>
<head>
  <title>Invalid Token</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Invalid Token</h1>
    <p>Your session may have expired. Please login again from the browser extension.</p>
  </div>
</body>
</html>`,
          { status: 401, headers: { "Content-Type": "text/html;charset=utf8" } }
        );
      }

      // If token came from query param, set cookie and redirect to clean URL
      if (tokenFromQuery) {
        const headers = new Headers({
          Location: `${url.origin}/stats`
        });
        headers.append(
          "Set-Cookie",
          `jwt=${token}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=31536000`
        );
        return new Response("Redirecting...", { status: 302, headers });
      }

      // Get user's visits
      const id = env.USER_STATS.idFromName(payload.sub);
      const stub = env.USER_STATS.get(id);
      const response = await stub.fetch(new Request("https://do/visits"));
      const visitsData = (await response.json()) as {
        visits: Array<{
          id: number;
          url: string;
          duration: number;
          visitedAt: string;
          title: string;
          description: string;
        }>;
      };

      // Build stats HTML - grouped by date
      let statsHtml = "";
      if (!visitsData.visits || visitsData.visits.length === 0) {
        statsHtml = '<div class="no-data">No websites tracked yet</div>';
      } else {
        // Group visits by date
        const visitsByDate: Record<string, typeof visitsData.visits> = {};
        for (const visit of visitsData.visits) {
          const date = new Date(visit.visitedAt).toLocaleDateString("en-US", {
            weekday: "long",
            year: "numeric",
            month: "long",
            day: "numeric"
          });
          if (!visitsByDate[date]) {
            visitsByDate[date] = [];
          }
          visitsByDate[date].push(visit);
        }

        // Build HTML for each date group
        for (const [date, visits] of Object.entries(visitsByDate)) {
          statsHtml += `<div class="date-group">
            <div class="date-header">${date}</div>`;

          for (const visit of visits) {
            const llmTextUrl = `https://llmtext.com/${visit.url}`;
            const visitTime = new Date(visit.visitedAt).toLocaleTimeString(
              "en-US",
              {
                hour: "2-digit",
                minute: "2-digit"
              }
            );

            const titleDisplay = visit.title
              ? escapeHtml(visit.title)
              : escapeHtml(visit.url);
            const descDisplay = visit.description
              ? `<div class="site-description">${escapeHtml(visit.description)}</div>`
              : "";

            const hostname = escapeHtml(
              new URL(
                visit.url.startsWith("http")
                  ? visit.url
                  : "https://" + visit.url
              ).hostname
            );
            const faviconUrl = `https://www.google.com/s2/favicons?domain=${hostname}&sz=32`;

            statsHtml += `
            <div class="site-entry" data-search="${escapeHtml(visit.title?.toLowerCase() || "")} ${escapeHtml(visit.url.toLowerCase())} ${escapeHtml(visit.description?.toLowerCase() || "")}">
              <a href="${visit.url.startsWith("http") ? escapeHtml(visit.url) : "https://" + escapeHtml(visit.url)}" target="_blank" rel="noopener noreferrer" class="site-link">
                <img class="site-favicon" src="${faviconUrl}" alt="" width="28" height="28">
                <div class="site-info">
                  <div class="site-name">${titleDisplay}</div>
                  <div class="site-url">${escapeHtml(visit.url)}</div>
                  ${descDisplay}
                  <div class="site-details">
                    ${visitTime} · ${formatTime(visit.duration)}
                  </div>
                </div>
              </a>
              <a href="${llmTextUrl}" target="_blank" rel="noopener noreferrer" class="context-btn" title="Look up context">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><path d="M11 8v6"/><path d="M8 11h6"/></svg>
              </a>
            </div>`;
          }

          statsHtml += `</div>`;
        }
      }

      const html = `<!DOCTYPE html>
<html>
<head>

  <title>Wilmake History - Stats</title>
<link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="shortcut icon" href="/favicon.ico" />
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
<link rel="manifest" href="/site.webmanifest" />
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
      background: #f5f5f5;
      min-height: 100vh;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      overflow: hidden;
    }
    .header {
      padding: 20px;
      background: #f8f9fa;
      border-bottom: 1px solid #eee;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .user-avatar {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      object-fit: cover;
    }
    .user-info { flex: 1; }
    .user-info h1 {
      margin: 0;
      font-size: 18px;
      color: #333;
    }
    .user-info p {
      margin: 4px 0 0 0;
      font-size: 14px;
      color: #666;
    }
    .github-btn { display: flex; align-items: center; color: #666; text-decoration: none; padding: 8px; border-radius: 50%; }
    .github-btn:hover { color: #333; background: #f0f0f0; }
    .logout-btn { padding: 8px 16px; background: none; border: 1px solid #ddd; border-radius: 6px; color: #666; font-size: 13px; cursor: pointer; text-decoration: none; }
    .logout-btn:hover { background: #f5f5f5; color: #333; border-color: #ccc; }
    .stats {
      padding: 0;
    }
    .search-bar {
      padding: 12px 20px;
      border-bottom: 1px solid #eee;
    }
    .search-bar input {
      width: 100%;
      padding: 10px 14px 10px 36px;
      border: 1px solid #dfe1e5;
      border-radius: 24px;
      font-size: 14px;
      outline: none;
      background: #fff url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%239aa0a6' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='M21 21l-4.35-4.35'/%3E%3C/svg%3E") 12px center no-repeat;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .search-bar input:focus {
      border-color: #4285f4;
      box-shadow: 0 1px 6px rgba(66,133,244,0.28);
    }
    .search-bar input::placeholder {
      color: #9aa0a6;
    }
    .site-entry {
      padding: 12px 20px;
      border-bottom: 1px solid #ebebeb;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .site-entry:last-child {
      border-bottom: none;
    }
    .site-entry:hover {
      background: #f8f9fa;
    }
    .site-link {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      flex: 1;
      text-decoration: none;
      color: inherit;
      min-width: 0;
    }
    .site-favicon {
      width: 28px;
      height: 28px;
      border-radius: 50%;
      background: #f1f3f4;
      flex-shrink: 0;
      margin-top: 2px;
    }
    .site-info {
      flex: 1;
      min-width: 0;
    }
    .site-name {
      font-size: 16px;
      color: #1a0dab;
      margin-bottom: 2px;
      line-height: 1.3;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .site-link:visited .site-name {
      color: #681da8;
    }
    .site-link:hover .site-name {
      text-decoration: underline;
    }
    .site-url {
      font-size: 12px;
      color: #202124;
      margin-bottom: 2px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .site-description {
      font-size: 13px;
      color: #4d5156;
      margin-bottom: 2px;
      line-height: 1.4;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }
    .site-details {
      font-size: 12px;
      color: #70757a;
      margin-top: 2px;
    }
    .date-group {
      margin-bottom: 0;
    }
    .date-header {
      background: #f0f4f8;
      padding: 12px 20px;
      font-weight: 600;
      color: #555;
      font-size: 14px;
      border-bottom: 1px solid #e0e0e0;
      position: sticky;
      top: 0;
      z-index: 1;
    }
    .context-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      color: #70757a;
      text-decoration: none;
      flex-shrink: 0;
      transition: background-color 0.2s, color 0.2s;
    }
    .context-btn:hover {
      background: #e8f0fe;
      color: #1a73e8;
    }
    .no-data {
      text-align: center;
      color: #999;
      padding: 40px 20px;
    }
    .refresh-note {
      text-align: center;
      padding: 15px;
      font-size: 12px;
      color: #999;
      border-top: 1px solid #eee;
    }
    .tabs {
      display: flex;
      border-bottom: 2px solid #eee;
      background: #f8f9fa;
    }
    .tab {
      padding: 12px 24px;
      font-size: 14px;
      font-weight: 500;
      color: #666;
      text-decoration: none;
      border-bottom: 2px solid transparent;
      margin-bottom: -2px;
      transition: color 0.2s, border-color 0.2s;
    }
    .tab:hover {
      color: #333;
    }
    .tab.active {
      color: #2196F3;
      border-bottom-color: #2196F3;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      ${payload.pfp ? `<img class="user-avatar" src="${payload.pfp}" alt="${payload.name}">` : ""}
      <div class="user-info">
        <h1>${payload.name}</h1>
        <p>@${payload.username}</p>
      </div>
      <a class="github-btn" href="https://github.com/janwilmake/browser-history" target="_blank" rel="noopener noreferrer" title="GitHub"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg></a>
      <a class="logout-btn" href="/logout">Logout</a>
    </div>
    <div class="tabs">
      <a class="tab" href="/">Installation</a>
      <a class="tab active" href="/stats">Activity</a>
      <a class="tab" href="/daily">Daily Summary</a>
    </div>
    <div class="search-bar">
      <input type="text" id="searchInput" placeholder="Search your browsing history..." autocomplete="off">
    </div>
    <div class="stats" id="statsContainer">
      ${statsHtml}
    </div>
    <div class="refresh-note">
      Refresh this page to see updated stats
    </div>
  </div>
  <script>
    const input = document.getElementById('searchInput');
    const container = document.getElementById('statsContainer');
    const entries = container.querySelectorAll('.site-entry');
    const dateGroups = container.querySelectorAll('.date-group');

    input.addEventListener('input', function() {
      const q = this.value.toLowerCase().trim();
      if (!q) {
        entries.forEach(e => e.style.display = '');
        dateGroups.forEach(g => g.style.display = '');
        return;
      }
      dateGroups.forEach(group => {
        const items = group.querySelectorAll('.site-entry');
        let anyVisible = false;
        items.forEach(entry => {
          const match = entry.dataset.search.includes(q);
          entry.style.display = match ? '' : 'none';
          if (match) anyVisible = true;
        });
        group.style.display = anyVisible ? '' : 'none';
      });
    });
  </script>
</body>
</html>`;

      return new Response(html, {
        headers: { "Content-Type": "text/html;charset=utf8" }
      });
    }

    // GET /daily - Daily summary page grouped by hostname (JWT from query param or cookie)
    if (url.pathname === "/daily") {
      const tokenFromQuery = url.searchParams.get("token");
      const tokenFromCookie = getCookie(request.headers.get("Cookie"), "jwt");
      const token = tokenFromQuery || tokenFromCookie;

      if (!token) {
        return new Response(
          `<!DOCTYPE html>
<html>
<head>
  <title>Not Authorized</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Not Authorized</h1>
    <p>Please login from the browser extension to view your stats.</p>
  </div>
</body>
</html>`,
          { status: 401, headers: { "Content-Type": "text/html;charset=utf8" } }
        );
      }

      const payload = await verifyJWT(token, env.JWT_SECRET);

      if (!payload) {
        return new Response(
          `<!DOCTYPE html>
<html>
<head>
  <title>Invalid Token</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Invalid Token</h1>
    <p>Your session may have expired. Please login again from the browser extension.</p>
  </div>
</body>
</html>`,
          { status: 401, headers: { "Content-Type": "text/html;charset=utf8" } }
        );
      }

      // If token came from query param, set cookie and redirect to clean URL
      if (tokenFromQuery) {
        const headers = new Headers({
          Location: `${url.origin}/daily`
        });
        headers.append(
          "Set-Cookie",
          `jwt=${token}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=31536000`
        );
        return new Response("Redirecting...", { status: 302, headers });
      }

      // Get user's visits
      const id = env.USER_STATS.idFromName(payload.sub);
      const stub = env.USER_STATS.get(id);
      const response = await stub.fetch(new Request("https://do/visits"));
      const visitsData = (await response.json()) as {
        visits: Array<{
          id: number;
          url: string;
          duration: number;
          visitedAt: string;
          title: string;
          description: string;
        }>;
      };

      // Build daily summary HTML - grouped by date, then by hostname
      let dailyHtml = "";
      if (!visitsData.visits || visitsData.visits.length === 0) {
        dailyHtml = '<div class="no-data">No websites tracked yet</div>';
      } else {
        // Group visits by date, then by hostname
        const dailyByHostname: Record<string, Record<string, number>> = {};
        for (const visit of visitsData.visits) {
          const date = new Date(visit.visitedAt).toLocaleDateString("en-US", {
            weekday: "long",
            year: "numeric",
            month: "long",
            day: "numeric"
          });
          const hostname = extractHostname(visit.url);
          if (!dailyByHostname[date]) {
            dailyByHostname[date] = {};
          }
          dailyByHostname[date][hostname] =
            (dailyByHostname[date][hostname] || 0) + visit.duration;
        }

        // Build HTML for each date group
        for (const [date, hostnames] of Object.entries(dailyByHostname)) {
          // Sort hostnames by total time descending
          const sorted = Object.entries(hostnames).sort((a, b) => b[1] - a[1]);
          const dayTotal = sorted.reduce((sum, [, time]) => sum + time, 0);

          dailyHtml += `<div class="date-group">
            <div class="date-header">
              <span>${date}</span>
              <span class="day-total">${formatTime(dayTotal)}</span>
            </div>`;

          for (const [hostname, totalSeconds] of sorted) {
            const barWidth = Math.max(
              2,
              Math.round((totalSeconds / sorted[0][1]) * 100)
            );

            dailyHtml += `
            <div class="site-entry">
              <div class="site-info">
                <div class="site-name">${escapeHtml(hostname)}</div>
                <div class="bar-container">
                  <div class="bar" style="width: ${barWidth}%"></div>
                </div>
              </div>
              <div class="time-badge">${formatTime(totalSeconds)}</div>
            </div>`;
          }

          dailyHtml += `</div>`;
        }
      }

      const dailyPageHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Wilmake History - Daily Summary</title>
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="shortcut icon" href="/favicon.ico" />
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
<link rel="manifest" href="/site.webmanifest" />
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
      background: #f5f5f5;
      min-height: 100vh;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      overflow: hidden;
    }
    .header {
      padding: 20px;
      background: #f8f9fa;
      border-bottom: 1px solid #eee;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .user-avatar {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      object-fit: cover;
    }
    .user-info { flex: 1; }
    .user-info h1 {
      margin: 0;
      font-size: 18px;
      color: #333;
    }
    .user-info p {
      margin: 4px 0 0 0;
      font-size: 14px;
      color: #666;
    }
    .github-btn { display: flex; align-items: center; color: #666; text-decoration: none; padding: 8px; border-radius: 50%; }
    .github-btn:hover { color: #333; background: #f0f0f0; }
    .logout-btn { padding: 8px 16px; background: none; border: 1px solid #ddd; border-radius: 6px; color: #666; font-size: 13px; cursor: pointer; text-decoration: none; }
    .logout-btn:hover { background: #f5f5f5; color: #333; border-color: #ccc; }
    .tabs {
      display: flex;
      border-bottom: 2px solid #eee;
      background: #f8f9fa;
    }
    .tab {
      padding: 12px 24px;
      font-size: 14px;
      font-weight: 500;
      color: #666;
      text-decoration: none;
      border-bottom: 2px solid transparent;
      margin-bottom: -2px;
      transition: color 0.2s, border-color 0.2s;
    }
    .tab:hover {
      color: #333;
    }
    .tab.active {
      color: #2196F3;
      border-bottom-color: #2196F3;
    }
    .stats {
      padding: 0;
    }
    .site-entry {
      padding: 12px 20px;
      border-bottom: 1px solid #eee;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    }
    .site-entry:last-child {
      border-bottom: none;
    }
    .site-entry:hover {
      background: #f9f9f9;
    }
    .site-info {
      flex: 1;
      min-width: 0;
    }
    .site-name {
      font-weight: 500;
      color: #333;
      margin-bottom: 6px;
      font-size: 14px;
    }
    .bar-container {
      height: 6px;
      background: #eee;
      border-radius: 3px;
      overflow: hidden;
    }
    .bar {
      height: 100%;
      background: #2196F3;
      border-radius: 3px;
      transition: width 0.3s;
    }
    .time-badge {
      background: #2196F3;
      color: white;
      padding: 6px 12px;
      border-radius: 16px;
      font-size: 13px;
      font-weight: bold;
      white-space: nowrap;
    }
    .date-group {
      margin-bottom: 0;
    }
    .date-header {
      background: #f0f4f8;
      padding: 12px 20px;
      font-weight: 600;
      color: #555;
      font-size: 14px;
      border-bottom: 1px solid #e0e0e0;
      position: sticky;
      top: 0;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .day-total {
      font-size: 13px;
      color: #2196F3;
      font-weight: 700;
    }
    .no-data {
      text-align: center;
      color: #999;
      padding: 40px 20px;
    }
    .refresh-note {
      text-align: center;
      padding: 15px;
      font-size: 12px;
      color: #999;
      border-top: 1px solid #eee;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      ${payload.pfp ? `<img class="user-avatar" src="${payload.pfp}" alt="${payload.name}">` : ""}
      <div class="user-info">
        <h1>${payload.name}</h1>
        <p>@${payload.username}</p>
      </div>
      <a class="github-btn" href="https://github.com/janwilmake/browser-history" target="_blank" rel="noopener noreferrer" title="GitHub"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg></a>
      <a class="logout-btn" href="/logout">Logout</a>
    </div>
    <div class="tabs">
      <a class="tab" href="/">Installation</a>
      <a class="tab" href="/stats">Activity</a>
      <a class="tab active" href="/daily">Daily Summary</a>
    </div>
    <div class="stats">
      ${dailyHtml}
    </div>
    <div class="refresh-note">
      Refresh this page to see updated stats
    </div>
  </div>
</body>
</html>`;

      return new Response(dailyPageHtml, {
        headers: { "Content-Type": "text/html;charset=utf8" }
      });
    }

    // POST /refresh - Refresh access token (returns new JWT)
    if (url.pathname === "/refresh" && request.method === "POST") {
      try {
        const body = (await request.json()) as { refresh_token: string };
        const { refresh_token } = body;

        if (!refresh_token) {
          return new Response(
            JSON.stringify({ error: "refresh_token required" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders }
            }
          );
        }

        const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${btoa(`${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`)}`
          },
          body: new URLSearchParams({
            refresh_token,
            grant_type: "refresh_token",
            client_id: env.X_CLIENT_ID
          })
        });

        const tokenData = (await tokenResponse.json()) as {
          access_token: string;
          refresh_token?: string;
          error?: string;
        };

        if (!tokenResponse.ok) {
          return new Response(
            JSON.stringify({ error: "refresh_failed", details: tokenData }),
            {
              status: tokenResponse.status,
              headers: { "Content-Type": "application/json", ...corsHeaders }
            }
          );
        }

        // Fetch updated user info
        interface XUserRefresh {
          id: string;
          username: string;
          name: string;
          profile_image_url?: string;
        }
        let userRefresh: XUserRefresh | null = null;
        try {
          const userResponse = await fetch(
            "https://api.x.com/2/users/me?user.fields=profile_image_url,username,name",
            { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
          );
          if (userResponse.ok) {
            const userData = (await userResponse.json()) as {
              data: XUserRefresh;
            };
            userRefresh = userData.data;
          }
        } catch (e) {
          console.error("Failed to fetch user info:", e);
        }

        if (!userRefresh) {
          return new Response(JSON.stringify({ error: "user_fetch_failed" }), {
            status: 500,
            headers: { "Content-Type": "application/json", ...corsHeaders }
          });
        }

        // Create new JWT
        const jwtPayload: JWTPayload = {
          sub: userRefresh.id,
          username: userRefresh.username,
          name: userRefresh.name,
          pfp: userRefresh.profile_image_url || "",
          iat: Math.floor(Date.now() / 1000)
        };

        const jwt = await createJWT(jwtPayload, env.JWT_SECRET);

        return new Response(
          JSON.stringify({
            jwt,
            refresh_token: tokenData.refresh_token || refresh_token,
            user: userRefresh
          }),
          {
            headers: { "Content-Type": "application/json", ...corsHeaders }
          }
        );
      } catch (error) {
        return new Response(
          JSON.stringify({
            error: "server_error",
            message: error instanceof Error ? error.message : "Unknown error"
          }),
          {
            status: 500,
            headers: { "Content-Type": "application/json", ...corsHeaders }
          }
        );
      }
    }

    // GET /admin - Admin page (janwilmake only)
    if (url.pathname === "/admin") {
      const tokenFromCookie = getCookie(request.headers.get("Cookie"), "jwt");
      const payload = tokenFromCookie
        ? await verifyJWT(tokenFromCookie, env.JWT_SECRET)
        : null;

      if (!payload || payload.username !== "janwilmake") {
        return new Response("Not authorized", { status: 403 });
      }

      const adminId = env.ADMIN_STATS.idFromName("global");
      const adminStub = env.ADMIN_STATS.get(adminId);
      const adminResponse = await adminStub.fetch(
        new Request("https://do/users")
      );
      const adminData = (await adminResponse.json()) as {
        users: AdminUserRow[];
      };

      let tableRows = "";
      for (const user of adminData.users) {
        const iatDate = new Date(user.iat * 1000).toISOString().split("T")[0];
        const activeDate = user.active_at
          ? new Date(user.active_at).toISOString().replace("T", " ").slice(0, 19)
          : "Never";
        const mcpActiveDate = user.mcp_active_at
          ? new Date(user.mcp_active_at).toISOString().replace("T", " ").slice(0, 19)
          : "Never";
        tableRows += `<tr>
          <td>${user.pfp ? `<img src="${escapeHtml(user.pfp)}" width="24" height="24" style="border-radius:50%;vertical-align:middle;margin-right:6px">` : ""}${escapeHtml(user.username)}</td>
          <td>${escapeHtml(user.name)}</td>
          <td>${escapeHtml(user.sub)}</td>
          <td>${iatDate}</td>
          <td>${activeDate}</td>
          <td>${user.track_count}</td>
          <td>${mcpActiveDate}</td>
          <td>${user.mcp_tool_call_count}</td>
        </tr>`;
      }

      const adminHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Admin - Wilmake History</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="shortcut icon" href="/favicon.ico" />
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
  <link rel="manifest" href="/site.webmanifest" />
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; min-height: 100vh; }
    .container { max-width: 1100px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
    .header { padding: 20px; background: #f8f9fa; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 12px; }
    .header h1 { margin: 0; font-size: 18px; color: #333; flex: 1; }
    .back-btn { padding: 8px 16px; background: none; border: 1px solid #ddd; border-radius: 6px; color: #666; font-size: 13px; text-decoration: none; }
    .back-btn:hover { background: #f5f5f5; color: #333; border-color: #ccc; }
    .content { padding: 24px; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th { text-align: left; padding: 10px 12px; background: #f0f4f8; color: #555; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e0e0e0; }
    td { padding: 10px 12px; border-bottom: 1px solid #eee; color: #333; }
    tr:hover td { background: #f9f9f9; }
    .count { text-align: center; font-size: 16px; color: #999; padding: 40px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Admin - Users (${adminData.users.length})</h1>
      <a class="back-btn" href="/">Back</a>
    </div>
    <div class="content">
      ${adminData.users.length === 0 ? '<div class="count">No users yet</div>' : `<table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Name</th>
            <th>Sub</th>
            <th>Signed Up</th>
            <th>Last Active</th>
            <th>Tracks</th>
            <th>MCP Last Active</th>
            <th>MCP Calls</th>
          </tr>
        </thead>
        <tbody>${tableRows}</tbody>
      </table>`}
    </div>
  </div>
</body>
</html>`;

      return new Response(adminHtml, {
        headers: { "Content-Type": "text/html;charset=utf8" },
      });
    }

    // GET / - Landing page
    if (url.pathname === "/") {
      const tokenFromCookie = getCookie(request.headers.get("Cookie"), "jwt");
      const payload = tokenFromCookie
        ? await verifyJWT(tokenFromCookie, env.JWT_SECRET)
        : null;

      if (!payload) {
        const html = `<!DOCTYPE html>
<html>
<head>
  <title>Wilmake History</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="shortcut icon" href="/favicon.ico" />
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
<link rel="manifest" href="/site.webmanifest" />
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: #f5f5f5; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
    .container { max-width: 620px; width: 100%; margin: 20px; }
    .hero { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; padding: 48px 40px 40px; }
    .logo { width: 200px; height: 200px; margin-bottom: 16px; }
    h1 { margin: 0 0 12px 0; color: #333; font-size: 24px; }
    .subtitle { color: #666; margin: 0 0 8px 0; font-size: 15px; line-height: 1.6; }
    .how { color: #999; margin: 0 0 28px 0; font-size: 13px; }
    a.btn { display: inline-block; padding: 14px 28px; background: #1da1f2; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; }
    a.btn:hover { background: #0d8ecf; }
    .diagram { margin: 32px 0 0; padding: 24px 0 0; border-top: 1px solid #eee; }
    .diagram-row { display: flex; align-items: center; justify-content: center; gap: 0; flex-wrap: wrap; }
    .diagram-node { display: flex; flex-direction: column; align-items: center; gap: 6px; }
    .diagram-icon { font-size: 28px; width: 56px; height: 56px; display: flex; align-items: center; justify-content: center; background: #f8f9fa; border-radius: 12px; border: 1px solid #e0e0e0; }
    .diagram-label { font-size: 11px; color: #888; font-weight: 500; }
    .diagram-arrow { color: #ccc; font-size: 20px; padding: 0 6px; margin-bottom: 18px; }
    .diagram-divider { width: 100%; text-align: center; color: #bbb; font-size: 11px; margin: 16px 0; text-transform: uppercase; letter-spacing: 1px; }
    .examples { margin-top: 20px; }
    .examples h2 { font-size: 14px; color: #999; text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 16px 0; font-weight: 600; }
    .chat { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; margin-bottom: 12px; }
    .chat:last-child { margin-bottom: 0; }
    .prompt { padding: 16px 20px; background: #f8f9fa; border-bottom: 1px solid #eee; font-size: 14px; color: #333; font-weight: 500; }
    .reply { padding: 16px 20px; font-size: 14px; color: #555; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <img class="logo" src="/icon.png" alt="Wilmake History">
      <h1>Give Your Lobster Your Browser History</h1>
      <p class="subtitle">Your browsing history, collected via a Chrome extension and exposed over MCP and a dashboard UI.</p>
      <p class="how">Install the extension, sign in, and let your AI assistant search your history.</p>
      <a class="btn" href="/login?source=web">Sign in with X</a>
      <div class="diagram">
        <div class="diagram-row">
          <div class="diagram-node"><div class="diagram-icon">&#x1F9D1;&#x200D;&#x1F4BB;</div><div class="diagram-label">You browse</div></div>
          <div class="diagram-arrow">&#x2192;</div>
          <div class="diagram-node"><div class="diagram-icon">&#x1F4E6;</div><div class="diagram-label">Extension</div></div>
          <div class="diagram-arrow">&#x2192;</div>
          <div class="diagram-node"><div class="diagram-icon">&#x1F5C4;&#xFE0F;</div><div class="diagram-label">Database</div></div>
        </div>
        <div class="diagram-divider">then</div>
        <div class="diagram-row">
          <div class="diagram-node"><div class="diagram-icon">&#x1F5C4;&#xFE0F;</div><div class="diagram-label">Database</div></div>
          <div class="diagram-arrow">&#x2192;</div>
          <div class="diagram-node"><div class="diagram-icon">&#x1F50C;</div><div class="diagram-label">MCP</div></div>
          <div class="diagram-arrow">&#x2192;</div>
          <div class="diagram-node"><div class="diagram-icon">&#x1F99E;</div><div class="diagram-label">Lobster</div></div>
        </div>
      </div>
    </div>
    <div class="examples">
      <h2>Example prompts</h2>
      <div class="chat">
        <div class="prompt">What was that article about React Server Components I read last week?</div>
        <div class="reply">You visited <strong>overreacted.io</strong> on Feb 18 - "React Server Components in Practice" - you spent about 12 minutes on it.</div>
      </div>
      <div class="chat">
        <div class="prompt">How much time did I spend on GitHub today?</div>
        <div class="reply">You've spent 1h 47m on github.com today across 23 visits. Your most visited repos were anthropics/claude-code and vercel/next.js.</div>
      </div>
      <div class="chat">
        <div class="prompt">Find that Hacker News thread about LLM benchmarks I saw yesterday</div>
        <div class="reply">Found it - you visited <strong>news.ycombinator.com</strong> yesterday at 3:42 PM: "Show HN: A new approach to LLM evaluation" with 342 comments. You spent 8 minutes on it.</div>
      </div>
    </div>
  </div>
</body>
</html>`;
        return new Response(html, {
          headers: { "Content-Type": "text/html;charset=utf8" }
        });
      }

      const mcpUrl = `${url.origin}/mcp`;

      const html = `<!DOCTYPE html>
<html>
<head>
  <title>Wilmake History</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="shortcut icon" href="/favicon.ico" />
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
<link rel="manifest" href="/site.webmanifest" />
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; min-height: 100vh; }
    .container { max-width: 900px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
    .header { padding: 20px; background: #f8f9fa; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 12px; }
    .user-avatar { width: 48px; height: 48px; border-radius: 50%; object-fit: cover; }
    .user-info { flex: 1; }
    .user-info h1 { margin: 0; font-size: 18px; color: #333; }
    .user-info p { margin: 4px 0 0 0; font-size: 14px; color: #666; }
    .github-btn { display: flex; align-items: center; color: #666; text-decoration: none; padding: 8px; border-radius: 50%; }
    .github-btn:hover { color: #333; background: #f0f0f0; }
    .logout-btn { padding: 8px 16px; background: none; border: 1px solid #ddd; border-radius: 6px; color: #666; font-size: 13px; cursor: pointer; text-decoration: none; }
    .logout-btn:hover { background: #f5f5f5; color: #333; border-color: #ccc; }
    .tabs { display: flex; border-bottom: 2px solid #eee; background: #f8f9fa; }
    .tab { padding: 12px 24px; font-size: 14px; font-weight: 500; color: #666; text-decoration: none; border-bottom: 2px solid transparent; margin-bottom: -2px; transition: color 0.2s, border-color 0.2s; }
    .tab:hover { color: #333; }
    .tab.active { color: #2196F3; border-bottom-color: #2196F3; }
    .content { padding: 24px; }
    .section { margin-bottom: 28px; }
    .section:last-child { margin-bottom: 0; }
    .section h2 { margin: 0 0 12px 0; font-size: 15px; color: #333; font-weight: 600; }
    .section p { margin: 0 0 12px 0; font-size: 14px; color: #666; line-height: 1.5; }
    .mcp-url-row { display: flex; gap: 8px; align-items: center; }
    .mcp-url { flex: 1; padding: 10px 14px; background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 8px; font-family: 'SF Mono', SFMono-Regular, Consolas, monospace; font-size: 13px; color: #333; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .copy-btn { padding: 10px 16px; background: #2196F3; color: white; border: none; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; white-space: nowrap; }
    .copy-btn:hover { background: #1976D2; }
    .copy-btn.copied { background: #4CAF50; }
    .iframe-wrapper { margin-top: 16px; display: flex; justify-content: center; }
    .iframe-wrapper iframe { border-radius: 8px; border: 1px solid #e0e0e0; }
    .step-num { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; background: #2196F3; color: white; border-radius: 50%; font-size: 13px; font-weight: 600; margin-right: 8px; flex-shrink: 0; }
    .step-title { display: flex; align-items: center; margin: 0 0 12px 0; font-size: 15px; color: #333; font-weight: 600; }
    .steps ol { margin: 0; padding: 0 0 0 20px; font-size: 14px; color: #555; line-height: 1.8; }
    .steps ol li { margin-bottom: 4px; }
    .steps code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 13px; font-family: 'SF Mono', SFMono-Regular, Consolas, monospace; }
    .steps a { color: #2196F3; text-decoration: none; }
    .steps a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      ${payload.pfp ? `<img class="user-avatar" src="${escapeHtml(payload.pfp)}" alt="${escapeHtml(payload.name)}">` : ""}
      <div class="user-info">
        <h1>${escapeHtml(payload.name)}</h1>
        <p>@${escapeHtml(payload.username)}</p>
      </div>
      <a class="github-btn" href="https://github.com/janwilmake/browser-history" target="_blank" rel="noopener noreferrer" title="GitHub"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg></a>
      ${payload.username === "janwilmake" ? '<a class="logout-btn" href="/admin">Admin</a>' : ""}
      <a class="logout-btn" href="/logout">Logout</a>
    </div>
    <div class="tabs">
      <a class="tab active" href="/">Installation</a>
      <a class="tab" href="/stats">Activity</a>
      <a class="tab" href="/daily">Daily Summary</a>
    </div>
    <div class="content steps">
      <div class="section">
        <div class="step-title"><span class="step-num">1</span> Install the Chrome Extension</div>
        <ol>
          <li><a href="https://github.com/janwilmake/browser-history/raw/refs/heads/main/chrome-extension.zip" download>Download chrome-extension.zip</a> and unzip it to a folder</li>
          <li>Open <code>chrome://extensions</code> in Chrome</li>
          <li>Enable <strong>Developer mode</strong> using the toggle in the top-right corner</li>
          <li>Click <strong>Load unpacked</strong> and select the unzipped folder</li>
          <li>The extension will appear in your toolbar - you're all set to start tracking</li>
        </ol>
      </div>
      <div class="section">
        <div class="step-title"><span class="step-num">2</span> Connect Your AI Assistant</div>
        <p>Use the MCP server URL below to give your AI assistant access to your browsing history.</p>
        <div class="mcp-url-row">
          <div class="mcp-url" id="mcpUrl">${escapeHtml(mcpUrl)}</div>
          <button class="copy-btn" id="copyBtn" onclick="copyMcpUrl()">Copy</button>
        </div>
      </div>
      <div class="section">
        <div class="iframe-wrapper">
          <iframe src="https://installthismcp.com/Browser%20History?url=https%3A%2F%2Fhistory.wilmake.com%2Fmcp&iframe=1" width="480" height="600" frameborder="0" title="Install Browser History"></iframe>
        </div>
      </div>
    </div>
  </div>
  <script>
    function copyMcpUrl() {
      const url = document.getElementById('mcpUrl').textContent;
      navigator.clipboard.writeText(url).then(() => {
        const btn = document.getElementById('copyBtn');
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
      });
    }
  </script>
</body>
</html>`;

      return new Response(html, {
        headers: { "Content-Type": "text/html;charset=utf8" }
      });
    }

    // GET /logout - Clear JWT cookie and redirect to /
    if (url.pathname === "/logout") {
      const headers = new Headers({ Location: "/" });
      headers.append(
        "Set-Cookie",
        `jwt=; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=0`
      );
      return new Response("Redirecting...", { status: 302, headers });
    }

    // Default: API info (JSON)
    return new Response(
      JSON.stringify({
        name: "Wilmake History",
        endpoints: {
          "/": "Landing page (GET)",
          "/login": "Start X OAuth flow (GET)",
          "/api/track": "Record a visit (POST with JWT)",
          "/api/stats": "Get stats as JSON (GET with JWT)",
          "/stats": "Stats HTML page",
          "/daily": "Daily summary by hostname",
          "/mcp": "MCP endpoint (POST JSON-RPC with Bearer token)"
        }
      }),
      { headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }
};

function redirectToExtension(
  origin: string,
  params: Record<string, string | undefined>
): Response {
  const callbackUrl = new URL(`${origin}${EXTENSION_CALLBACK_PATH}`);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      callbackUrl.searchParams.set(key, value);
    }
  }

  const headers = new Headers({
    Location: callbackUrl.toString()
  });

  // Clear OAuth cookies
  headers.append("Set-Cookie", "x_oauth_state=; Max-Age=0; Path=/");
  headers.append("Set-Cookie", "x_code_verifier=; Max-Age=0; Path=/");
  headers.append("Set-Cookie", "x_redirect_uri=; Max-Age=0; Path=/");

  return new Response("Redirecting...", { status: 307, headers });
}
