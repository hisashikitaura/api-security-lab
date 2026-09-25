import type { ApiResult } from "../api";

const INTERESTING_HEADERS = [
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "x-ratelimit-limit",
  "x-ratelimit-remaining",
  "retry-after",
];

export function ResultBox({ result }: { result: ApiResult | null }) {
  if (!result) {
    return (
      <section className="card result">
        <h2>レスポンス</h2>
        <p className="hint">まだリクエストしていません</p>
      </section>
    );
  }
  const statusClass =
    result.status >= 500
      ? "st-5xx"
      : result.status >= 400
        ? "st-4xx"
        : "st-2xx";

  const shownHeaders = Object.entries(result.headers).filter(([k]) =>
    INTERESTING_HEADERS.includes(k.toLowerCase()),
  );

  return (
    <section className="card result">
      <h2>
        レスポンス{" "}
        <span className={`status ${statusClass}`}>HTTP {result.status}</span>
      </h2>
      {shownHeaders.length > 0 && (
        <div className="header-compare">
          <h3>注目レスポンスヘッダー</h3>
          <ul>
            {shownHeaders.map(([k, v]) => (
              <li key={k}>
                <code>{k}</code>: {v}
              </li>
            ))}
          </ul>
        </div>
      )}
      <pre>{JSON.stringify(result.data, null, 2)}</pre>
    </section>
  );
}
