import EmptyState from "./EmptyState";
import ErrorState from "./ErrorState";
import LoadingState from "./LoadingState";

import "../styles/components/DataTable.scss";

function getRowKey(
  row,
  rowIndex,
  rowKey
) {
  if (typeof rowKey === "function") {
    return rowKey(row, rowIndex);
  }

  if (
    typeof rowKey === "string" &&
    row?.[rowKey] !== undefined
  ) {
    return row[rowKey];
  }

  return (
    row?.id ??
    row?.device_id ??
    rowIndex
  );
}

export default function DataTable({
  columns,
  rows,
  rowKey = "id",
  loading = false,
  error = "",
  onRetry,
  emptyTitle = "표시할 데이터가 없습니다.",
  emptyDescription,
  minWidth = 900,
  tableLabel = "데이터 목록",
  rowClassName,
  onRowClick,
}) {
  const safeColumns =
    Array.isArray(columns)
      ? columns
      : [];

  const safeRows =
    Array.isArray(rows)
      ? rows
      : [];

  if (
    loading &&
    safeRows.length === 0
  ) {
    return <LoadingState />;
  }

  if (
    error &&
    safeRows.length === 0
  ) {
    return (
      <ErrorState
        message={error}
        onRetry={onRetry}
      />
    );
  }

  if (safeRows.length === 0) {
    return (
      <EmptyState
        title={emptyTitle}
        description={
          emptyDescription
        }
      />
    );
  }

  return (
    <div className="data-table">
      {error && (
        <div className="inline-error">
          <span>
            최신 데이터를 불러오지 못해
            이전 데이터를 표시합니다.
          </span>

          {onRetry && (
            <button
              type="button"
              className="retry-link"
              onClick={onRetry}
            >
              다시 시도
            </button>
          )}
        </div>
      )}

      {loading && (
        <div
          className="refresh-indicator"
          role="status"
        >
          최신 데이터를 불러오는 중...
        </div>
      )}

      <div className="table-scroll">
        <table
          className="table"
          style={{
            minWidth,
          }}
          aria-label={tableLabel}
        >
          <thead>
            <tr>
              {safeColumns.map(
                (column) => (
                  <th
                    key={column.key}
                    className={
                      column.className
                    }
                    style={{
                      width:
                        column.width,
                      textAlign:
                        column.align ||
                        "left",
                    }}
                    scope="col"
                  >
                    {column.header}
                  </th>
                )
              )}
            </tr>
          </thead>

          <tbody>
            {safeRows.map(
              (row, rowIndex) => {
                const key = getRowKey(
                  row,
                  rowIndex,
                  rowKey
                );

                const customRowClass =
                  typeof rowClassName ===
                  "function"
                    ? rowClassName(
                        row,
                        rowIndex
                      )
                    : rowClassName;

                const clickable =
                  typeof onRowClick ===
                  "function";

                return (
                  <tr
                    key={key}
                    className={[
                      customRowClass,
                      clickable
                        ? "clickable"
                        : "",
                    ]
                      .filter(Boolean)
                      .join(" ")}
                    onClick={
                      clickable
                        ? () =>
                            onRowClick(
                              row
                            )
                        : undefined
                    }
                  >
                    {safeColumns.map(
                      (column) => {
                        const value =
                          row?.[
                            column.key
                          ];

                        const content =
                          typeof column.render ===
                          "function"
                            ? column.render(
                                value,
                                row,
                                rowIndex
                              )
                            : value ??
                              "-";

                        return (
                          <td
                            key={
                              column.key
                            }
                            className={
                              column.cellClassName
                            }
                            style={{
                              textAlign:
                                column.align ||
                                "left",
                            }}
                          >
                            {content}
                          </td>
                        );
                      }
                    )}
                  </tr>
                );
              }
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
