# API Security — デモと概念の対応表

このラボは **ローカル教育専用** です。意図的に脆弱なルート（`/api/vuln/...`）と、対になる安全なルート（`/api/safe/...`）を並べています。所有していないシステムへの攻撃・スキャンには使わないでください。

## OWASP API Security Top 10（関連箇所）

### v1

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

### v2

| デモ | ルート | 概念 | OWASP API Top 10（目安） |
|------|--------|------|--------------------------|
| CSRF セッション | `POST /api/meta/csrf/login` | Cookie セッション + CSRF トークン発行 | ブラウザ連携（API2/API8 関連） |
| CSRF（脆弱） | `POST /api/vuln/csrf/transfer` | Cookie のみで状態変更（トークンなし） | CSRF（Web 古典）＋ API セッション設計 |
| CSRF（安全） | `POST /api/safe/csrf/transfer` | `X-CSRF-Token` 必須 + SameSite 説明 | CSRF 対策 |
| JWT 改ざん（脆弱） | `GET /api/vuln/jwt/me` | 署名検証なし・`alg:none` 受理 | **API2 Broken Authentication** |
| JWT 改ざん（安全） | `GET /api/safe/jwt/me` | HMAC (HS256) 署名検証 | API2 対策 |
| 書き込み IDOR（脆弱） | `PUT/DELETE /api/vuln/notes/:id` | 認証済みでも所有者チェックなし | **API1**（write-side） |
| 書き込み IDOR（安全） | `PUT/DELETE /api/safe/notes/:id` | 更新・削除でも所有権照合 | API1 対策 |
| ヘッダー欠落 | `GET /api/vuln/headers-demo` | CSP 等なし | **API8 Security Misconfiguration** |
| ヘッダー付与 | `GET /api/safe/headers-demo` | CSP / XFO / nosniff / Referrer-Policy 等 | API8 対策 |
| OpenAPI 文書 | `GET /api/openapi.json` / `.yaml` | ラボ API サブセットの仕様 | API9 Improper Inventory Management（関連） |
| OpenAPI 検査 | `POST /api/safe/openapi-check` | 未宣言パス・フィールド検出 | API9 対策の入り口 |

参照: [OWASP API Security Top 10](https://owasp.org/API-Security/)

## 学習のポイント（日本語）

### 1. 認証（Authentication）
- **誰か**を確認する仕組み。
- APIキーは簡便だが共有秘密なので漏洩時の影響が大きい。
- JWT は署名で改ざん検知、`exp` で寿命を制御できる。
- **署名を検証しない**・`alg:none` を許す実装は、トークン改ざんによるなりすまし・権限昇格につながる。

### 2. 認可 / BOLA（Authorization）
- **何をしてよいか**を確認する仕組み。認証済みでも他人のデータは読めない・書けないようにする。
- オブジェクト ID を推測・列挙される前提で、**読み取りだけでなく PUT/DELETE でも**所有者チェックを入れる。

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

### 6. CSRF と SameSite（v2）
- ブラウザはログイン Cookie を自動添付する。別サイトからの POST でも Cookie が付くと、意図しない状態変更が起きる（CSRF）。
- **対策**: 状態変更に CSRF トークン（ヘッダー）を要求する（Synchronizer Token）。
- Cookie の **SameSite=Lax / Strict** でクロスサイト送信を抑える（Lax はトップレベル GET 遷移では送る。Strict はより厳しい）。
- CORS と CSRF は別物。CORS を正しくしても「Cookie + 状態変更」の CSRF は別途対策が必要。

### 7. セキュリティヘッダー（v2）
- **Content-Security-Policy (CSP)**: 読み込めるスクリプト等を制限し XSS の影響を抑える。
- **X-Frame-Options**: iframe 埋め込みを拒否しクリックジャッキングを緩和。
- **X-Content-Type-Options: nosniff**: MIME スニッフィングによる実行を防ぐ。
- **Referrer-Policy**: リファラに載せる情報量を制限。
- 欠落は **API8 Security Misconfiguration** の典型例。

### 8. OpenAPI インベントリ（v2）
- 実装されているパス・メソッド・フィールドを仕様として明示する。
- 未宣言のパス（シャドー API）や、仕様にないフィールド受信は、攻撃面の見落としにつながる（API9）。
- このラボの `openapi-check` は、サンプルリクエストを仕様と突合する簡易デモ。

## シードデータ

| ユーザー | パスワード | ノート ID | 注文 ID |
|----------|------------|-----------|---------|
| alice | alice123 | n-alice-1 | o-alice-1 |
| bob | bob123 | n-bob-1 | o-bob-1 |

デモ API キー: `lab-demo-key`
