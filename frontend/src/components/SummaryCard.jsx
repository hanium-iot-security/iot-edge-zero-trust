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
        `summary-card-${normalizedStatus}`,
        interactive
          ? "summary-card-clickable"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      onClick={onClick}
    >
      <div className="summary-card-header">
        <span className="summary-card-title">
          {title}
        </span>

        {icon && (
          <span
            className="summary-card-icon"
            aria-hidden="true"
          >
            {icon}
          </span>
        )}
      </div>

      <strong className="summary-card-value">
        {value ?? "-"}
      </strong>

      {description && (
        <p className="summary-card-description">
          {description}
        </p>
      )}

      {footer && (
        <div className="summary-card-footer">
          {footer}
        </div>
      )}
    </Element>
  );
}