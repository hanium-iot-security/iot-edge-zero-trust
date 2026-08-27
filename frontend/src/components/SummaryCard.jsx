import "../styles/components/SummaryCard.scss";

function normalizeStatus(status) {
  return String(status || "default")
    .trim()
    .toLowerCase()
    .replaceAll(" ", "_")
    .replaceAll("-", "_");
}

export default function SummaryCard({
  title,
  value,
  description,
  status = "default",
  icon,
  footer,
  onClick,
}) {
  const interactive =
    typeof onClick === "function";

  const normalizedStatus =
    normalizeStatus(status);

  const Element = interactive
    ? "button"
    : "article";

  return (
    <Element
      type={
        interactive
          ? "button"
          : undefined
      }
      className={[
        "summary-card",
        `status-${normalizedStatus}`,
        interactive
          ? "clickable"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      onClick={onClick}
    >
      <div className="card-header">
        <span className="card-title">
          {title}
        </span>

        {icon && (
          <span
            className="card-icon"
            aria-hidden="true"
          >
            {icon}
          </span>
        )}
      </div>

      <strong className="card-value">
        {value ?? "-"}
      </strong>

      {description && (
        <p className="description">
          {description}
        </p>
      )}

      {footer && (
        <div className="footer">
          {footer}
        </div>
      )}
    </Element>
  );
}
