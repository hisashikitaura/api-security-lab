# API Security — デモと概念の対応表

このラボは **ローカル教育専用** です。意図的に脆弱なルート（`/api/vuln/...`）と、対になる安全なルート（`/api/safe/...`）を並べています。所有していないシステムへの攻撃・スキャンには使わないでください。

## OWASP API Security Top 10（関連箇所）

| デモ | ルート | 概念 | OWASP API Top 10（目安） |
|------|--------|------|--------------------------|
| APIキー認証 | `GET /api/vuln/apikey/ping` | 共有秘密のヘッダー認証。漏洩・追跡の難しさ | API2 Broken Authentication（関連） |
| JWT ログイン | `POST /api/safe/auth/login` | 署名付きトークン発行 | API2 |
| JWT 検証 | `GET /api/safe/auth/me` | 署名 + `exp` 検証 | API2 |
| 期限切れ JWT | `POST /api/safe/auth/login-short` → `/me` | 期限切れトークンの拒否 | API2 |
| BOLA（脆弱） | `GET /api/vuln/notes/:id` | IDだけで他人リソース取得 | **API1 Broken Object Level Authorization** |
| BOLA（安全） | `GET /api/safe/notes/:id` | JWT のユーザーと `ownerId` 照合 | API1 対策 |
| 注文 BOLA | `GET /api/vuln/orders/:id` | 同じ欠陥を注文で再現 | API1 |
| Mass Assignment（脆弱） | `POST /api/vuln/profile` | ボディ全体マージで `role` 昇格 | **API3 Broken Object Property Level Authorization**（旧 Mass Assignment） |
| Mass Assignment（安全） | `POST /api/safe/profile` | ホワイトリスト更新 | API3 対策 |
| レート制限 | `GET /api/safe/rate-limited` | N 回超で 429 | **API4 Unrestricted Resource Consumption** 対策 |
| CORS 説明 | `GET /api/safe/cors-info` | ブラウザのオリジン制限（認可ではない） | 補足（ブラウザ制御） |
| シークレット配置 | `GET /api/safe/secrets-demo` + `VITE_` デモ | クライアント露出 vs サーバー専用 | API8 Security Misconfiguration（関連） |

参照: [OWASP API Security Top 10](https://owasp.org/API-Security/)

## 学習のポイント（日本語）

### 1. 認証（Authentication）
- **誰か**を確認する仕組み。
- APIキーは簡便だが共有秘密なので漏洩時の影響が大きい。
- JWT は署名で改ざん検知、`exp` で寿命を制御できる。

### 2. 認可 / BOLA（Authorization）
- **何をしてよいか**を確認する仕組み。認証済みでも他人のデータは読めないようにする。
- オブジェクト ID を推測・列挙される前提で、必ず所有者チェックを入れる。

### 3. Mass Assignment
- クライアントが送った JSON をそのまま DB/モデルに載せると、想定外のフィールド（`role`, `isAdmin`, `balance` など）が書き換わる。
- 許可リスト（allowlist）で更新可能フィールドを制限する。

### 4. レート制限
- ログイン試行や高価な API を無制限に叩かれると、総当たりや資源枯渇につながる。
- HTTP 429 と `Retry-After` / `X-RateLimit-*` でクライアントに伝える。

### 5. CORS と秘密情報
- CORS は **ブラウザ** 向けの読み取り制限。サーバー側の認可や攻撃者の直接アクセスを止めない。
- Vite の `VITE_` 環境変数はバンドルに埋め込まれる → **秘密を入れてはいけない**。
- API 秘密・署名鍵はサーバープロセスの環境変数やシークレットマネージャのみ。

## シードデータ

| ユーザー | パスワード | ノート ID | 注文 ID |
|----------|------------|-----------|---------|
| alice | alice123 | n-alice-1 | o-alice-1 |
| bob | bob123 | n-bob-1 | o-bob-1 |

デモ API キー: `lab-demo-key`
