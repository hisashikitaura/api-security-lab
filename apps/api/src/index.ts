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
import { requireApiKey, requireJwt, issueJwt, type LabJwtPayload } from "./auth.js";
import {
  DEMO_API_KEY,
  SERVER_SECRET,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW_MS,
  findUserByUsername,
  findNoteById,
  findOrderById,
  notes,
  orders,
  profiles,
  rateBuckets,
  resetProfiles,
  type User,
} from "./store.js";

type Variables = {
  user: User;
  jwt: LabJwtPayload;
};

const app = new Hono<{ Variables: Variables }>();

// CORS for Vite dev origin — educational demo of Access-Control-* headers
app.use(
  "*",
  cors({
    origin: ["http://localhost:5173", "http://127.0.0.1:5173"],
    allowHeaders: ["Content-Type", "Authorization", "X-API-Key"],
    allowMethods: ["GET", "POST", "PUT", "OPTIONS"],
    exposeHeaders: ["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"],
  }),
);

app.get("/api/health", (c) =>
  c.json({ ok: true, service: "api-security-lab", port: 8787 }),
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
  // Allow short expiry for the "expired token" demo (min 1s)
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
  // VULN: no ownership check — any id returns any note (BOLA)
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

// ─── Mass assignment ────────────────────────────────────────────────

app.post("/api/vuln/profile", requireJwt, async (c) => {
  const user = c.get("user");
  const body = await c.req.json<Record<string, unknown>>();
  const current = profiles.get(user.id)!;
  // VULN: spreads entire body — client can set role: "admin"
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
  // SAFE: whitelist only
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
      allowHeaders: ["Content-Type", "Authorization", "X-API-Key"],
    },
    misconception:
      "CORSはサーバー側の認可ではない。攻撃者がcurlで直接叩くことは止められない。",
  }),
);

const port = 8787;
console.log(`[api-security-lab] listening on http://localhost:${port}`);
console.log(`[api-security-lab] WARNING: local education only — vulnerable routes enabled`);

serve({ fetch: app.fetch, port });

export default app;
