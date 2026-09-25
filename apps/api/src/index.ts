/**
 * API Security Lab — educational HTTP API
 *
 * WARNING: Intentionally vulnerable routes under /api/vuln/* exist for
 * local learning only. Do NOT expose this server to the internet or use
 * techniques against systems you do not own.
 */
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { getCookie, setCookie } from "hono/cookie";
import {
  requireApiKey,
  requireJwt,
  issueJwt,
  decodeJwtUnsafe,
  forgeUnsignedJwt,
  type LabJwtPayload,
} from "./auth.js";
import {
  DEMO_API_KEY,
  SERVER_SECRET,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW_MS,
  SESSION_COOKIE,
  CSRF_HEADER,
  findUserByUsername,
  findUserById,
  findNoteById,
  findOrderById,
  notes,
  orders,
  profiles,
  rateBuckets,
  resetProfiles,
  resetNotes,
  updateNote,
  deleteNote,
  createCsrfSession,
  findCsrfSession,
  type User,
} from "./store.js";
import {
  openApiDocument,
  openApiAsYaml,
  checkAgainstOpenApi,
} from "./openapi.js";

type Variables = {
  user: User;
  jwt: LabJwtPayload;
};

const app = new Hono<{ Variables: Variables }>();

const SECURITY_HEADER_NAMES = [
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
] as const;

// CORS for Vite dev origin — educational demo of Access-Control-* headers
app.use(
  "*",
  cors({
    origin: ["http://localhost:5173", "http://127.0.0.1:5173"],
    allowHeaders: [
      "Content-Type",
      "Authorization",
      "X-API-Key",
      CSRF_HEADER,
    ],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    exposeHeaders: [
      "X-RateLimit-Limit",
      "X-RateLimit-Remaining",
      "Retry-After",
      ...SECURITY_HEADER_NAMES,
    ],
  }),
);

app.get("/api/health", (c) =>
  c.json({ ok: true, service: "api-security-lab", port: 8787, version: 2 }),
);

app.get("/api/meta", (c) =>
  c.json({
    demoApiKey: DEMO_API_KEY,
    users: [
      { username: "alice", password: "alice123", noteId: "n-alice-1", bobNoteId: "n-bob-1" },
      { username: "bob", password: "bob123", noteId: "n-bob-1", aliceNoteId: "n-alice-1" },
    ],
    rateLimit: { max: RATE_LIMIT_MAX, windowMs: RATE_LIMIT_WINDOW_MS },
    warning:
      "ローカル教育専用です。所有していないシステムへの攻撃に使わないでください。",
  }),
);

// ─── OpenAPI document ───────────────────────────────────────────────

app.get("/api/openapi.json", (c) => c.json(openApiDocument));

app.get("/api/openapi.yaml", (c) =>
  c.text(openApiAsYaml(), 200, {
    "Content-Type": "application/yaml; charset=utf-8",
  }),
);

app.post("/api/safe/openapi-check", async (c) => {
  const body = await c.req.json<{
    method?: string;
    path?: string;
    body?: unknown;
  }>();
  const result = checkAgainstOpenApi(body);
  return c.json(result);
});

// ─── Auth: API key vs JWT ───────────────────────────────────────────

app.get("/api/vuln/apikey/ping", requireApiKey, (c) =>
  c.json({
    ok: true,
    mode: "vuln",
    message:
      "APIキー認証成功。キーは共有秘密なので漏洩・ローテーションが難しい（デモ）。",
  }),
);

app.post("/api/safe/auth/login", async (c) => {
  const body = await c.req.json<{ username?: string; password?: string; expiresIn?: number }>();
  const user = findUserByUsername(body.username ?? "");
  if (!user || user.password !== body.password) {
    return c.json({ error: "invalid_credentials", message: "ユーザー名またはパスワードが違います" }, 401);
  }
  const expiresIn = Math.max(1, Math.min(body.expiresIn ?? 3600, 3600));
  const token = await issueJwt(user.id, user.username, user.role, expiresIn);
  return c.json({
    token,
    expiresIn,
    user: { id: user.id, username: user.username, displayName: user.displayName, role: user.role },
  });
});

app.get("/api/safe/auth/me", requireJwt, (c) => {
  const user = c.get("user");
  return c.json({
    ok: true,
    mode: "safe",
    user: { id: user.id, username: user.username, displayName: user.displayName, role: user.role },
    message: "JWT の署名と有効期限を検証済みです。",
  });
});

/** Issue a JWT that expires in 2 seconds — for UI expiry demo */
app.post("/api/safe/auth/login-short", async (c) => {
  const body = await c.req.json<{ username?: string; password?: string }>();
  const user = findUserByUsername(body.username ?? "");
  if (!user || user.password !== body.password) {
    return c.json({ error: "invalid_credentials", message: "ユーザー名またはパスワードが違います" }, 401);
  }
  const token = await issueJwt(user.id, user.username, user.role, 2);
  return c.json({
    token,
    expiresIn: 2,
    hint: "2秒後に /api/safe/auth/me を呼ぶと token_expired になります",
    user: { id: user.id, username: user.username },
  });
});

// ─── Authorization / BOLA (Broken Object Level Authorization) ───────

app.get("/api/vuln/notes/:id", (c) => {
  const note = findNoteById(c.req.param("id") ?? "");
  if (!note) return c.json({ error: "not_found" }, 404);
  return c.json({
    mode: "vuln",
    warning: "所有者チェックなし — IDを知っていれば他人のノートが読める（BOLA）",
    note,
  });
});

app.get("/api/safe/notes/:id", requireJwt, (c) => {
  const note = findNoteById(c.req.param("id") ?? "");
  if (!note) return c.json({ error: "not_found" }, 404);
  const user = c.get("user");
  if (note.ownerId !== user.id) {
    return c.json(
      {
        error: "forbidden",
        mode: "safe",
        message: "このノートの所有者ではありません（BOLA対策: 所有権チェック）",
      },
      403,
    );
  }
  return c.json({ mode: "safe", note });
});

app.get("/api/vuln/orders/:id", (c) => {
  const order = findOrderById(c.req.param("id") ?? "");
  if (!order) return c.json({ error: "not_found" }, 404);
  return c.json({
    mode: "vuln",
    warning: "注文も所有者チェックなし（BOLA）",
    order,
  });
});

app.get("/api/safe/orders/:id", requireJwt, (c) => {
  const order = findOrderById(c.req.param("id") ?? "");
  if (!order) return c.json({ error: "not_found" }, 404);
  const user = c.get("user");
  if (order.ownerId !== user.id) {
    return c.json({ error: "forbidden", mode: "safe", message: "他人の注文にはアクセスできません" }, 403);
  }
  return c.json({ mode: "safe", order });
});

app.get("/api/meta/notes", (c) =>
  c.json({
    notes: notes.map((n) => ({ id: n.id, ownerId: n.ownerId, title: n.title })),
    orders: orders.map((o) => ({ id: o.id, ownerId: o.ownerId, item: o.item })),
  }),
);

// ─── Write-side IDOR (v2) ───────────────────────────────────────────

app.put("/api/vuln/notes/:id", requireJwt, async (c) => {
  const id = c.req.param("id") ?? "";
  const note = findNoteById(id);
  if (!note) return c.json({ error: "not_found" }, 404);
  const body = await c.req.json<{ title?: string; body?: string }>();
  // VULN: authenticated but no ownership check on write
  const updated = updateNote(id, body)!;
  return c.json({
    mode: "vuln",
    warning:
      "書き込み側 IDOR — 認証済みでも所有者チェックなし。他人のノートを改ざんできる",
    note: updated,
    actor: c.get("user").username,
  });
});

app.delete("/api/vuln/notes/:id", requireJwt, (c) => {
  const id = c.req.param("id") ?? "";
  const note = findNoteById(id);
  if (!note) return c.json({ error: "not_found" }, 404);
  // VULN: no ownership check
  deleteNote(id);
  return c.json({
    mode: "vuln",
    warning: "書き込み側 IDOR — 他人のノートを削除できてしまった",
    deletedId: id,
    previousOwnerId: note.ownerId,
    actor: c.get("user").username,
  });
});

app.put("/api/safe/notes/:id", requireJwt, async (c) => {
  const id = c.req.param("id") ?? "";
  const note = findNoteById(id);
  if (!note) return c.json({ error: "not_found" }, 404);
  const user = c.get("user");
  if (note.ownerId !== user.id) {
    return c.json(
      {
        error: "forbidden",
        mode: "safe",
        message: "他人のノートは更新できません（書き込み側 IDOR 対策）",
      },
      403,
    );
  }
  const body = await c.req.json<{ title?: string; body?: string }>();
  const updated = updateNote(id, body)!;
  return c.json({ mode: "safe", note: updated });
});

app.delete("/api/safe/notes/:id", requireJwt, (c) => {
  const id = c.req.param("id") ?? "";
  const note = findNoteById(id);
  if (!note) return c.json({ error: "not_found" }, 404);
  const user = c.get("user");
  if (note.ownerId !== user.id) {
    return c.json(
      {
        error: "forbidden",
        mode: "safe",
        message: "他人のノートは削除できません（書き込み側 IDOR 対策）",
      },
      403,
    );
  }
  deleteNote(id);
  return c.json({ mode: "safe", deletedId: id });
});

app.post("/api/meta/reset-notes", (c) => {
  resetNotes();
  return c.json({ ok: true, message: "ノートを初期状態に戻しました", notes });
});

// ─── Mass assignment ────────────────────────────────────────────────

app.post("/api/vuln/profile", requireJwt, async (c) => {
  const user = c.get("user");
  const body = await c.req.json<Record<string, unknown>>();
  const current = profiles.get(user.id)!;
  const updated = { ...current, ...body, id: user.id, username: user.username };
  profiles.set(user.id, updated as typeof current);
  return c.json({
    mode: "vuln",
    warning: "ボディをそのままマージ — role など特権フィールドが書き換え可能（Mass Assignment）",
    profile: profiles.get(user.id),
  });
});

app.post("/api/safe/profile", requireJwt, async (c) => {
  const user = c.get("user");
  const body = await c.req.json<{ displayName?: string; bio?: string }>();
  const current = profiles.get(user.id)!;
  const updated = {
    ...current,
    displayName:
      typeof body.displayName === "string" ? body.displayName : current.displayName,
    bio: typeof body.bio === "string" ? body.bio : current.bio,
  };
  profiles.set(user.id, updated);
  return c.json({
    mode: "safe",
    message: "displayName / bio のみ許可（role は無視）",
    profile: updated,
    ignoredFields: Object.keys(body).filter((k) => k !== "displayName" && k !== "bio"),
  });
});

app.get("/api/safe/profile/me", requireJwt, (c) => {
  const user = c.get("user");
  return c.json({ profile: profiles.get(user.id) });
});

app.post("/api/meta/reset-profiles", (c) => {
  resetProfiles();
  return c.json({ ok: true, message: "プロフィールを初期状態に戻しました" });
});

// ─── Rate limit ─────────────────────────────────────────────────────

app.get("/api/safe/rate-limited", (c) => {
  const key =
    c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
    c.req.header("x-real-ip") ||
    "local-lab-client";
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    bucket = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  const remaining = Math.max(0, RATE_LIMIT_MAX - bucket.count);
  c.header("X-RateLimit-Limit", String(RATE_LIMIT_MAX));
  c.header("X-RateLimit-Remaining", String(remaining));
  if (bucket.count > RATE_LIMIT_MAX) {
    const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
    c.header("Retry-After", String(retryAfter));
    return c.json(
      {
        error: "rate_limited",
        message: `リクエスト過多です。${RATE_LIMIT_MAX}回 / ${RATE_LIMIT_WINDOW_MS / 1000}秒 を超えました。`,
        retryAfter,
      },
      429,
    );
  }
  return c.json({
    ok: true,
    count: bucket.count,
    remaining,
    limit: RATE_LIMIT_MAX,
    resetAt: new Date(bucket.resetAt).toISOString(),
  });
});

app.post("/api/meta/reset-rate-limit", (c) => {
  rateBuckets.clear();
  return c.json({ ok: true });
});

// ─── CORS + secrets education ───────────────────────────────────────

app.get("/api/safe/secrets-demo", (c) =>
  c.json({
    serverOnlySecretPresent: Boolean(SERVER_SECRET),
    serverOnlySecretHint: "サーバープロセス内のみ。VITE_ には載せない。",
    wrongPattern:
      "VITE_API_SECRET=... はビルド成果物に埋め込まれるためブラウザから読める",
    rightPattern:
      "秘密はサーバー環境変数 / シークレットマネージャのみ。フロントは公開可能な設定だけ。",
    corsNote:
      "この API は Access-Control-Allow-Origin で localhost:5173 のみ許可（教育用CORS）。",
  }),
);

app.get("/api/safe/cors-info", (c) =>
  c.json({
    title: "CORS（Cross-Origin Resource Sharing）",
    summary:
      "ブラウザは別オリジンへの JS からの読み取りを制限する。サーバーが ACAO 等で許可した場合のみフロントがレスポンスを読める。",
    thisLab: {
      allowedOrigin: "http://localhost:5173",
      allowHeaders: ["Content-Type", "Authorization", "X-API-Key", CSRF_HEADER],
    },
    misconception:
      "CORSはサーバー側の認可ではない。攻撃者がcurlで直接叩くことは止められない。",
  }),
);

// ─── CSRF (v2) ──────────────────────────────────────────────────────

app.post("/api/meta/csrf/login", async (c) => {
  const body = await c.req.json<{ username?: string; password?: string }>();
  const user = findUserByUsername(body.username ?? "alice");
  if (!user || user.password !== (body.password ?? "alice123")) {
    return c.json({ error: "invalid_credentials" }, 401);
  }
  const session = createCsrfSession(user);
  // Intentionally omit SameSite to illustrate cookie-based CSRF risk on lax/legacy
  setCookie(c, SESSION_COOKIE, session.sessionId, {
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
  });
  return c.json({
    ok: true,
    username: user.username,
    csrfToken: session.csrfToken,
    balance: session.balance,
    cookie: SESSION_COOKIE,
    sameSiteNote:
      "SameSite=Lax はトップレベルGET遷移では送るが、クロスサイトPOSTでは送らない（現代ブラウザ）。それでも同一サイトリクエストや一部ケースでは CSRF トークンが必要。Strict はより厳しい。",
  });
});

app.get("/api/meta/csrf/session", (c) => {
  const sid = getCookie(c, SESSION_COOKIE);
  const session = findCsrfSession(sid);
  if (!session) {
    return c.json({ loggedIn: false, message: "セッショクッキがありません。先に CSRF ログインしてください" });
  }
  return c.json({
    loggedIn: true,
    username: session.username,
    balance: session.balance,
    csrfToken: session.csrfToken,
  });
});

app.post("/api/vuln/csrf/transfer", async (c) => {
  const sid = getCookie(c, SESSION_COOKIE);
  const session = findCsrfSession(sid);
  if (!session) {
    return c.json({ error: "unauthorized", message: "セッションCookieが必要です" }, 401);
  }
  const body = await c.req.json<{ amount?: number; to?: string }>().catch(() => ({} as { amount?: number; to?: string }));
  const amount = Math.max(1, Math.min(body.amount ?? 1000, session.balance));
  session.balance -= amount;
  // VULN: cookie auth only — no CSRF token check (cross-site style POST would succeed)
  return c.json({
    mode: "vuln",
    warning:
      "CSRF脆弱 — Cookieセッションだけで状態変更を受付。悪意あるサイトからのクロスオリジンPOST（credentials込み）でも送金できてしまう",
    transferred: amount,
    to: body.to ?? "attacker",
    balance: session.balance,
    csrfChecked: false,
  });
});

app.post("/api/safe/csrf/transfer", async (c) => {
  const sid = getCookie(c, SESSION_COOKIE);
  const session = findCsrfSession(sid);
  if (!session) {
    return c.json({ error: "unauthorized", message: "セッションCookieが必要です" }, 401);
  }
  const headerToken = c.req.header(CSRF_HEADER);
  if (!headerToken || headerToken !== session.csrfToken) {
    return c.json(
      {
        error: "csrf_rejected",
        mode: "safe",
        message:
          "CSRFトークン不一致または欠落。状態変更には X-CSRF-Token が必要です（Synchronizer Token）",
        sameSiteHint:
          "加えて Cookie に SameSite=Strict（または Lax）を付け、クロスサイト送信を抑える",
      },
      403,
    );
  }
  const body = await c.req.json<{ amount?: number; to?: string }>().catch(() => ({} as { amount?: number; to?: string }));
  const amount = Math.max(1, Math.min(body.amount ?? 1000, session.balance));
  session.balance -= amount;
  return c.json({
    mode: "safe",
    message: "CSRFトークン検証OK。正当な同一サイトUIからのリクエストと判断",
    transferred: amount,
    to: body.to ?? "bob",
    balance: session.balance,
    csrfChecked: true,
  });
});

// ─── JWT tampering (v2) ─────────────────────────────────────────────

app.post("/api/meta/jwt/forge-unsigned", async (c) => {
  const body = await c.req.json<{
    sub?: string;
    username?: string;
    role?: string;
  }>();
  const token = forgeUnsignedJwt({
    sub: body.sub ?? "u-alice",
    username: body.username ?? "alice",
    role: body.role ?? "admin",
  });
  return c.json({
    token,
    header: { alg: "none", typ: "JWT" },
    payload: {
      sub: body.sub ?? "u-alice",
      username: body.username ?? "alice",
      role: body.role ?? "admin",
    },
    warning:
      "教育用の署名なしJWT。脆弱エンドポイントだけがこれを受け入れます。",
  });
});

app.get("/api/vuln/jwt/me", (c) => {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) {
    return c.json({ error: "unauthorized", message: "Bearer トークンが必要です" }, 401);
  }
  const token = auth.slice(7);
  const payload = decodeJwtUnsafe(token);
  if (!payload?.sub) {
    return c.json({ error: "invalid_token", message: "デコードできませんでした" }, 401);
  }
  // VULN: trust claims without signature — forged role/sub accepted
  const user = findUserById(payload.sub) ?? {
    id: payload.sub,
    username: String(payload.username ?? "forged"),
    displayName: String(payload.username ?? "forged"),
    role: (payload.role as User["role"]) ?? "user",
    password: "",
  };
  return c.json({
    mode: "vuln",
    warning:
      "JWT改ざん脆弱 — 署名検証なし（alg:none / 偽ペイロードを信頼）。sub や role を自由に書き換え可能",
    trustedClaims: {
      sub: payload.sub,
      username: payload.username,
      role: payload.role,
    },
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: payload.role ?? user.role,
    },
  });
});

app.get("/api/safe/jwt/me", requireJwt, (c) => {
  const user = c.get("user");
  const jwt = c.get("jwt");
  return c.json({
    mode: "safe",
    message: "HMAC (HS256) 署名と exp を検証済み。改ざんトークンは拒否されます",
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: user.role,
    },
    claims: { sub: jwt.sub, username: jwt.username, role: jwt.role },
  });
});

// ─── Security headers (v2) ──────────────────────────────────────────

app.get("/api/vuln/headers-demo", (c) => {
  // Intentionally omit security headers
  return c.json({
    mode: "vuln",
    warning:
      "セキュリティヘッダー欠落 — XSS・クリックジャッキング・MIMEスニッフィング等へのブラウザ防御が弱い",
    missing: [...SECURITY_HEADER_NAMES],
    jp: {
      "Content-Security-Policy": "読み込めるスクリプト/リソースを制限（XSS緩和）",
      "X-Frame-Options": "iframe埋め込み禁止でクリックジャッキング緩和",
      "X-Content-Type-Options": "nosniff — MIME推測による実行を防止",
      "Referrer-Policy": "リファラに載せる情報量を制限",
      "Permissions-Policy": "カメラ等のブラウザ機能を制限",
    },
    setOnResponse: {},
  });
});

app.get("/api/safe/headers-demo", (c) => {
  const headers: Record<string, string> = {
    "Content-Security-Policy":
      "default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
  };
  for (const [k, v] of Object.entries(headers)) {
    c.header(k, v);
  }
  return c.json({
    mode: "safe",
    message: "主要セキュリティヘッダーを付与済み",
    setOnResponse: headers,
    jp: {
      "Content-Security-Policy":
        "CSP — 許可オリジン以外のスクリプト実行を抑制し XSS 影響を抑える",
      "X-Frame-Options":
        "DENY — 他サイトの iframe に埋め込まれない（クリックジャッキング対策）",
      "X-Content-Type-Options":
        "nosniff — Content-Type を尊重し、ブラウザの MIME スニッフィングを止める",
      "Referrer-Policy":
        "strict-origin-when-cross-origin — クロスオリジンではオリジンのみ送る",
      "Permissions-Policy": "不要な強力 API（カメラ等）を無効化",
      "Cross-Origin-Opener-Policy": "同一オリジンの opener 分離で Spectre 系リスク低減",
      "Cross-Origin-Resource-Policy": "他オリジンからの読み込みを制限",
    },
  });
});

const port = 8787;
console.log(`[api-security-lab] listening on http://localhost:${port}`);
console.log(`[api-security-lab] WARNING: local education only — vulnerable routes enabled`);

serve({ fetch: app.fetch, port });

export default app;
