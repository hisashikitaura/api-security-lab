export interface Concept {
  id: string;
  name: string;
  explanation: string;
  at: string;
}

export const CONCEPT_TEXT: Record<string, { name: string; explanation: string }> = {
  apikey: {
    name: "APIキー認証",
    explanation:
      "共有秘密をヘッダーで送る簡易認証。漏洩しやすく、誰が使ったか追跡しにくい。",
  },
  jwt: {
    name: "JWT（JSON Web Token）",
    explanation:
      "署名付きトークン。サーバーは署名と exp（有効期限）を検証して本人性を確認する。",
  },
  jwt_expired: {
    name: "JWT 期限切れ",
    explanation:
      "exp を過ぎたトークンは拒否される。短い寿命 + リフレッシュで漏洩影響を抑える。",
  },
  bola_vuln: {
    name: "BOLA（脆弱）",
    explanation:
      "オブジェクトIDだけで取得し所有者を見ない。他人のノート/注文が読めてしまう。",
  },
  bola_safe: {
    name: "BOLA対策",
    explanation:
      "JWTのユーザーIDとリソースのownerIdを照合し、他人なら403を返す。",
  },
  mass_vuln: {
    name: "Mass Assignment（脆弱）",
    explanation:
      "リクエストボディをそのままモデルにマージすると role など特権フィールドを書き換えられる。",
  },
  mass_safe: {
    name: "Mass Assignment対策",
    explanation:
      "許可フィールド（ホワイトリスト）だけ更新する。role はクライアントから受けない。",
  },
  rate_limit: {
    name: "レート制限",
    explanation:
      "短時間の過剰リクエストを429で拒否し、総当たりやDoS風の乱用を抑える。",
  },
  cors: {
    name: "CORS",
    explanation:
      "ブラウザが別オリジンのレスポンス読み取りを制限。サーバーの認可そのものではない。",
  },
  secrets: {
    name: "秘密情報の置き場所",
    explanation:
      "VITE_ 変数はフロントバンドルに入る。API秘密はサーバー専用環境変数に置く。",
  },
  csrf_vuln: {
    name: "CSRF（脆弱）",
    explanation:
      "Cookieセッションだけで状態変更すると、別サイトからの偽装POSTで勝手に操作される。",
  },
  csrf_safe: {
    name: "CSRF対策 + SameSite",
    explanation:
      "状態変更に CSRF トークンを要求し、Cookie に SameSite=Lax/Strict を付けてクロスサイト送信を抑える。",
  },
  jwt_tamper_vuln: {
    name: "JWT改ざん（脆弱）",
    explanation:
      "署名を検証せず alg:none や偽ペイロードを信頼すると、sub/role を自由に書き換えられる。",
  },
  jwt_tamper_safe: {
    name: "JWT改ざん対策",
    explanation:
      "サーバー側で HMAC 等の署名を検証し、改ざん・alg:none トークンを拒否する。",
  },
  idor_write_vuln: {
    name: "書き込み側 IDOR（脆弱）",
    explanation:
      "認証済みでも PUT/DELETE で所有者を見ないと、他人のリソースを改ざん・削除できる。",
  },
  idor_write_safe: {
    name: "書き込み側 IDOR対策",
    explanation:
      "更新・削除でも JWT のユーザーと ownerId を照合し、他人なら 403 を返す。",
  },
  headers_vuln: {
    name: "セキュリティヘッダー欠落",
    explanation:
      "CSP / X-Frame-Options 等が無いと、XSS・クリックジャッキング・MIMEスニッフィングの被害が広がりやすい。",
  },
  headers_safe: {
    name: "セキュリティヘッダー",
    explanation:
      "CSP・X-Frame-Options・nosniff・Referrer-Policy 等でブラウザ側の防御層を足す。",
  },
  openapi_check: {
    name: "OpenAPI クロスチェック",
    explanation:
      "実装リクエストを仕様と突合し、未宣言パスや追加フィールド（シャドーAPI / 過剰受信）を検出する。",
  },
};
