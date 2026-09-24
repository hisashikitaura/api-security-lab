import type { Concept } from "../concepts";

export function ConceptFeed({
  concepts,
  onClear,
}: {
  concepts: Concept[];
  onClear: () => void;
}) {
  return (
    <aside className="feed">
      <div className="feed-header">
        <h2>いま学んだ概念</h2>
        <button type="button" className="linkish" onClick={onClear}>
          クリア
        </button>
      </div>
      {concepts.length === 0 ? (
        <p className="feed-empty">
          左のデモボタンを押すと、関連するセキュリティ概念がここに溜まります。
        </p>
      ) : (
        <ul>
          {concepts.map((c) => (
            <li key={c.id}>
              <div className="feed-name">{c.name}</div>
              <div className="feed-exp">{c.explanation}</div>
              <div className="feed-at">{c.at}</div>
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}
