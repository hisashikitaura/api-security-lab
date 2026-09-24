import type { ApiResult } from "../api";

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
  return (
    <section className="card result">
      <h2>
        レスポンス{" "}
        <span className={`status ${statusClass}`}>HTTP {result.status}</span>
      </h2>
      <pre>{JSON.stringify(result.data, null, 2)}</pre>
    </section>
  );
}
