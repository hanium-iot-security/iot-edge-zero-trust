import "../styles/components/Pagination.scss";

export default function Pagination({
  currentPage,
  totalPages,
  total,
  pageSize,
  onPrevious,
  onNext,
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

  return (
    <nav
      className="pagination"
      aria-label="페이지 이동"
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
