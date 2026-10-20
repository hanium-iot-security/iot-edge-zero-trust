import { evidenceLabel } from "../utils/uiText";
import "../styles/components/JsonViewer.scss";

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

export default function JsonViewer({
  data,
  translateKeys = false,
}) {
  if (
    !data ||
    typeof data !== "object"
  ) {
    return (
      <div className="json-empty">
        표시할 상세 증거가 없습니다.
      </div>
    );
  }

  return (
    <dl className="json-viewer">
      {Object.entries(data).map(
        ([key, value]) => (
          <div
            className="json-row"
            key={key}
          >
            <dt>{translateKeys ? evidenceLabel(key) : key}</dt>

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
