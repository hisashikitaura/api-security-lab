# API Security Lab

日本語 UI で **API セキュリティ** を学ぶローカル教育用 Web アプリです。  
意図的に脆弱な HTTP エンドポイント（`/api/vuln/...`）と、対になる安全な実装（`/api/safe/...`）を並べ、操作のたびに概念パネルへ日本語でログします。

## ⚠️ WARNING（必ず読んでください）

- **ローカル教育専用**です。意図的に脆弱なルートが含まれます。
- **インターネットへ公開しないでください。**
- **所有していないシステム・本番環境へのテスト・攻撃には使わないでください。**
- デモキー（`lab-demo-key`）やパスワードは本物の秘密ではありません。

## 学べるデモ（v1）

1. **認証** — APIキーヘッダー vs JWT（発行・署名/期限検証・期限切れ失敗）
2. **認可 / BOLA** — Alice が Bob のノート ID を取る（脆弱は成功、安全は 403）
3. **Mass Assignment** — ボディに `role: admin` を混ぜる（脆弱は昇格、安全は無視）
4. **レート制限** — 連打で HTTP 429
5. **CORS + 秘密情報** — CORS の意味と、`VITE_` に秘密を置いてはいけない理由
6. **いま学んだ概念** — サイドパネルに概念名と短い日本語解説を蓄積

詳細な OWASP API Top 10 対応表: [docs/API-SECURITY.md](./docs/API-SECURITY.md)

## 学習パス（おすすめ順）

1. APIキーで ping → 誤ったキーで 401
2. Alice / Bob で JWT 発行 → `/me` 成功
3. 短い寿命 JWT で期限切れを体験
4. 認証なしで Bob のノート（脆弱）→ Alice JWT で Bob のノート（安全・403）
5. `role: admin` を送って Mass Assignment を比較
6. レート制限を 8 回連打
7. CORS / `VITE_` シークレットパネルを読む

## 必要環境

- Node.js 18+
- npm 9+

## セットアップと起動

```bash
git clone https://github.com/hisashikitaura/api-security-lab.git
cd api-security-lab
npm install
npm run dev
```

- Web UI: http://localhost:5173  
- API: http://localhost:8787  
- Vite が `/api` を API へプロキシします（別オリジンでも CORS 許可済み）

片方だけ起動する場合:

```bash
npm run dev:api   # :8787
npm run dev:web   # :5173
```

## ビルド

```bash
npm run build
```

`apps/api`（`tsc`）と `apps/web`（`tsc` + `vite build`）の両方が通る必要があります。

## シードアカウント

| ユーザー | パスワード | ノート | 注文 |
|----------|------------|--------|------|
| alice | alice123 | n-alice-1 | o-alice-1 |
| bob | bob123 | n-bob-1 | o-bob-1 |

APIキー: `lab-demo-key`

## 構成

```
apps/api   Hono + TypeScript（port 8787）
apps/web   Vite + React + TypeScript（port 5173）
docs/      概念と OWASP 対応
```

## ライセンス

教育目的のサンプルです。脆弱ルートを悪用した責任は負いません。
