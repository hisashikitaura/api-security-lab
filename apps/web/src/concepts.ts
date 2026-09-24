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
};
