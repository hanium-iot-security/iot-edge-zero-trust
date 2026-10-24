import "../styles/components/Pagination.scss";

export default function Pagination({
  currentPage,
  totalPages,
  total,
  pageSize,
  onPrevious,
  onNext,
  onPageChange,
  ariaLabel = "페이지 이동",
  disabled = false,
}) {
  const safeCurrentPage =
    Math.max(
      Number(currentPage) || 1,
      1
    );

  const safeTotalPages =
    Math.max(
      Number(totalPages) || 1,
      1
    );

  const safeTotal =
    Number(total) || 0;

  const safePageSize =
    Number(pageSize) || 0;

  const firstItem =
    safeTotal === 0
      ? 0
      : (safeCurrentPage - 1) *
          safePageSize +
        1;

  const lastItem =
    safeTotal === 0
      ? 0
      : Math.min(
          safeCurrentPage *
            safePageSize,
          safeTotal
        );

  const firstPage = Math.max(1, Math.min(safeCurrentPage - 2, safeTotalPages - 4));
  const pageNumbers = Array.from(
    { length: Math.min(5, safeTotalPages) },
    (_, index) => firstPage + index
  );

  return (
    <nav
      className={onPageChange ? "pagination pagination--numbered" : "pagination"}
      aria-label={ariaLabel}
    >
      <button
        type="button"
        className="page-button"
        onClick={onPrevious}
        disabled={
          disabled ||
          safeCurrentPage <= 1
        }
      >
        이전
      </button>

      {onPageChange && (
        <div className="page-numbers">
          {pageNumbers.map((page) => (
            <button
              key={page}
              type="button"
              className="page-button page-number"
              aria-label={`${page} 페이지`}
              aria-current={page === safeCurrentPage ? "page" : undefined}
              disabled={disabled}
              onClick={() => onPageChange(page)}
            >
              {page}
            </button>
          ))}
        </div>
      )}

      <div className="page-info">
        <strong>
          {safeCurrentPage}
        </strong>

        <span>
          / {safeTotalPages} 페이지
        </span>

        <span className="range">
          {firstItem}–{lastItem}
          {" / "}
          총 {safeTotal}건
        </span>
      </div>

      <button
        type="button"
        className="page-button"
        onClick={onNext}
        disabled={
          disabled ||
          safeCurrentPage >=
            safeTotalPages
        }
      >
        다음
      </button>
    </nav>
  );
}
