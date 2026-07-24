function formatValue(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "-";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "object") {
    return JSON.stringify(
      value,
      null,
      2
    );
  }

  return String(value);
}

function formatKey(key) {
  return String(key)
    .replaceAll("_", " ")
    .replace(
      /\b\w/g,
      (letter) =>
        letter.toUpperCase()
    );
}

export default function JsonViewer({
  data,
}) {
  if (
    !data ||
    typeof data !== "object"
  ) {
    return (
      <div className="json-viewer-empty">
        표시할 상세 증거가 없습니다.
      </div>
    );
  }

  return (
    <dl className="json-viewer">
      {Object.entries(data).map(
        ([key, value]) => (
          <div
            className="json-viewer-row"
            key={key}
          >
            <dt>{formatKey(key)}</dt>

            <dd>
              {typeof value ===
              "object" ? (
                <pre>
                  {formatValue(value)}
                </pre>
              ) : (
                formatValue(value)
              )}
            </dd>
          </div>
        )
      )}
    </dl>
  );
}