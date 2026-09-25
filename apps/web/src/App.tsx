import { useCallback, useState } from "react";
import { api, type ApiResult } from "./api";
import { CONCEPT_TEXT, type Concept } from "./concepts";
import { ConceptFeed } from "./components/ConceptFeed";
import { ResultBox } from "./components/ResultBox";

type TokenState = {
  alice?: string;
  bob?: string;
  shortLived?: string;
};

export default function App() {
  const [concepts, setConcepts] = useState<Concept[]>([]);
  const [tokens, setTokens] = useState<TokenState>({});
  const [last, setLast] = useState<ApiResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [rateLog, setRateLog] = useState<string[]>([]);

  const logConcept = useCallback((key: keyof typeof CONCEPT_TEXT) => {
    const c = CONCEPT_TEXT[key];
    setConcepts((prev) => [
      {
        id: `${key}-${Date.now()}`,
        name: c.name,
        explanation: c.explanation,
        at: new Date().toLocaleTimeString("ja-JP"),
      },
      ...prev,
    ]);
  }, []);

  const run = useCallback(
    async (fn: () => Promise<ApiResult>, concept?: keyof typeof CONCEPT_TEXT) => {
      setBusy(true);
      try {
        const res = await fn();
        setLast(res);
        if (concept) logConcept(concept);
        return res;
      } finally {
        setBusy(false);
      }
    },
    [logConcept],
  );

  const login = async (who: "alice" | "bob") => {
    const password = who === "alice" ? "alice123" : "bob123";
    const res = await run(
      () =>
        api("/api/safe/auth/login", {
          method: "POST",
          body: JSON.stringify({ username: who, password }),
        }),
      "jwt",
    );
    const data = res.data as { token?: string };
    if (data?.token) {
      setTokens((t) => ({ ...t, [who]: data.token }));
    }
  };

  return (
    <div className="layout">
      <header className="header">
        <div>
          <h1>API Security Lab</h1>
          <p className="subtitle">
            脆弱エンドポイントと安全エンドポイントを並べて学ぶ — ローカル教育専用
          </p>
        </div>
        <div className="badge-warn">
          ⚠️ 教育デモのみ。所有していないシステムには使わないでください
        </div>
      </header>

      <div className="main">
        <div className="demos">
          {/* 1. Auth */}
          <section className="card">
            <h2>1. 認証 — APIキー vs JWT</h2>
            <p className="hint">
              デモAPIキー: <code>lab-demo-key</code> ／ ユーザー: alice/alice123, bob/bob123
            </p>
            <div className="row">
              <button
                disabled={busy}
                onClick={() =>
                  run(
                    () =>
                      api("/api/vuln/apikey/ping", {
                        headers: { "X-API-Key": "lab-demo-key" },
                      }),
                    "apikey",
                  )
                }
              >
                脆弱: APIキーで ping
              </button>
              <button
                disabled={busy}
                onClick={() =>
                  run(() =>
                    api("/api/vuln/apikey/ping", {
                      headers: { "X-API-Key": "wrong-key" },
                    }),
                  )
                }
              >
                誤ったキー（401）
              </button>
              <button disabled={busy} onClick={() => login("alice")}>
                安全: Alice で JWT 発行
              </button>
              <button disabled={busy} onClick={() => login("bob")}>
                安全: Bob で JWT 発行
              </button>
              <button
                disabled={busy || !tokens.alice}
                onClick={() =>
                  run(
                    () =>
                      api("/api/safe/auth/me", {
                        headers: { Authorization: `Bearer ${tokens.alice}` },
                      }),
                    "jwt",
                  )
                }
              >
                JWT で /me（Alice）
              </button>
              <button
                disabled={busy}
                onClick={async () => {
                  const loginRes = await run(
                    () =>
                      api("/api/safe/auth/login-short", {
                        method: "POST",
                        body: JSON.stringify({
                          username: "alice",
                          password: "alice123",
                        }),
                      }),
                  );
                  const token = (loginRes.data as { token?: string })?.token;
                  if (!token) return;
                  setTokens((t) => ({ ...t, shortLived: token }));
                  setRateLog((l) => [
                    "短い寿命JWTを取得。3秒待ってから検証します…",
                    ...l,
                  ]);
                  await new Promise((r) => setTimeout(r, 3000));
                  await run(
                    () =>
                      api("/api/safe/auth/me", {
                        headers: { Authorization: `Bearer ${token}` },
                      }),
                    "jwt_expired",
                  );
                }}
              >
                期限切れJWTデモ（2秒寿命→待機→失敗）
              </button>
            </div>
            <p className="token-status">
              Alice JWT: {tokens.alice ? "取得済み" : "未取得"} ／ Bob JWT:{" "}
              {tokens.bob ? "取得済み" : "未取得"}
            </p>
          </section>

          {/* 2. BOLA */}
          <section className="card">
            <h2>2. 認可 / BOLA — Alice が Bob のノートを取る</h2>
            <p className="hint">
              Bobのノート ID: <code>n-bob-1</code> ／ Aliceのノート: <code>n-alice-1</code>
            </p>
            <div className="row">
              <button
                disabled={busy}
                className="vuln"
                onClick={() =>
                  run(() => api("/api/vuln/notes/n-bob-1"), "bola_vuln")
                }
              >
                脆弱: 認証なしで Bob のノート取得
              </button>
              <button
                disabled={busy || !tokens.alice}
                className="vuln"
                onClick={() =>
                  run(
                    () =>
                      api("/api/safe/notes/n-bob-1", {
                        headers: { Authorization: `Bearer ${tokens.alice}` },
                      }),
                    "bola_safe",
                  )
                }
              >
                安全: Alice JWT で Bob のノート（→403）
              </button>
              <button
                disabled={busy || !tokens.alice}
                className="safe"
                onClick={() =>
                  run(() =>
                    api("/api/safe/notes/n-alice-1", {
                      headers: { Authorization: `Bearer ${tokens.alice}` },
                    }),
                  )
                }
              >
                安全: Alice が自分のノート（→200）
              </button>
              <button
                disabled={busy}
                onClick={() =>
                  run(() => api("/api/vuln/orders/o-bob-1"), "bola_vuln")
                }
              >
                脆弱: Bob の注文を ID だけで取得
              </button>
            </div>
          </section>

          {/* 3. Mass assignment */}
          <section className="card">
            <h2>3. Mass Assignment — role: admin を送り込む</h2>
            <div className="row">
              <button
                disabled={busy || !tokens.alice}
                className="vuln"
                onClick={() =>
                  run(
                    () =>
                      api("/api/vuln/profile", {
                        method: "POST",
                        headers: { Authorization: `Bearer ${tokens.alice}` },
                        body: JSON.stringify({
                          displayName: "Alice (hacked)",
                          role: "admin",
                          bio: "権限昇格デモ",
                        }),
                      }),
                    "mass_vuln",
                  )
                }
              >
                脆弱: role=admin 付きで更新
              </button>
              <button
                disabled={busy || !tokens.alice}
                className="safe"
                onClick={() =>
                  run(
                    () =>
                      api("/api/safe/profile", {
                        method: "POST",
                        headers: { Authorization: `Bearer ${tokens.alice}` },
                        body: JSON.stringify({
                          displayName: "Alice Safe",
                          role: "admin",
                          bio: "ホワイトリストのみ反映",
                        }),
                      }),
                    "mass_safe",
                  )
                }
              >
                安全: 同じボディでも role は無視
              </button>
              <button
                disabled={busy}
                onClick={() =>
                  run(() =>
                    api("/api/meta/reset-profiles", { method: "POST" }),
                  )
                }
              >
                プロフィール初期化
              </button>
            </div>
          </section>

          {/* 4. Rate limit */}
          <section className="card">
            <h2>4. レート制限 — 連打で 429</h2>
            <p className="hint">ウィンドウ内 5 回まで。超えると 429 + Retry-After</p>
            <div className="row">
              <button
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  const lines: string[] = [];
                  try {
                    for (let i = 1; i <= 8; i++) {
                      const res = await api("/api/safe/rate-limited");
                      lines.push(
                        `#${i} → HTTP ${res.status}` +
                          (res.status === 429 ? " (rate limited!)" : ""),
                      );
                      setRateLog([...lines].reverse());
                      setLast(res);
                      if (res.status === 429) logConcept("rate_limit");
                    }
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                スパムクリック相当（8回連続）
              </button>
              <button
                disabled={busy}
                onClick={() =>
                  run(() =>
                    api("/api/meta/reset-rate-limit", { method: "POST" }),
                  )
                }
              >
                レート制限リセット
              </button>
            </div>
            {rateLog.length > 0 && (
              <pre className="rate-log">{rateLog.join("\n")}</pre>
            )}
          </section>

          {/* 5. CORS + secrets */}
          <section className="card">
            <h2>5. CORS と 秘密情報の置き場所</h2>
            <div className="secrets-panel">
              <div>
                <h3>CORS</h3>
                <p>
                  このラボの API は <code>Access-Control-Allow-Origin:
                  http://localhost:5173</code> のみ許可。ブラウザの別オリジン制限であり、
                  curl 等の直接アクセスは止められません（認可の代わりにはならない）。
                </p>
                <button
                  disabled={busy}
                  onClick={() =>
                    run(() => api("/api/safe/cors-info"), "cors")
                  }
                >
                  CORS 説明を API から取得
                </button>
              </div>
              <div>
                <h3>秘密情報</h3>
                <p>
                  ❌ 悪い例: Vite の <code>VITE_</code> 環境変数に秘密を置くと、
                  ビルド成果物に埋め込まれブラウザから読めます。
                </p>
                <p className="wrong-secret">
                  import.meta.env.VITE_WRONG_API_SECRET ={" "}
                  <code>{import.meta.env.VITE_WRONG_API_SECRET ?? "(未設定)"}</code>
                </p>
                <p>
                  ✅ 正しい例: サーバー専用の環境変数 / シークレットマネージャのみ。
                  フロントには公開可能な設定だけ。
                </p>
                <button
                  disabled={busy}
                  onClick={() =>
                    run(() => api("/api/safe/secrets-demo"), "secrets")
                  }
                >
                  サーバー側シークレット説明を取得
                </button>
              </div>
            </div>
          </section>
        </div>

        <aside className="sidebar">
          <ResultBox result={last} />
          <ConceptFeed concepts={concepts} onClear={() => setConcepts([])} />
        </aside>
      </div>
    </div>
  );
}
