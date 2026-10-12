import {
  useEffect,
  useId,
} from "react";

import "../styles/components/DetailModal.scss";

export default function DetailModal({
  open,
  title,
  description,
  children,
  onClose,
  size = "medium",
  footer,
  closeDisabled = false,
}) {
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    if (!open) {
      return undefined;
    }

    function handleKeyDown(event) {
      if (
        event.key === "Escape" &&
        !closeDisabled
      ) {
        onClose?.();
      }
    }

    const previousOverflow =
      document.body.style.overflow;

    document.body.style.overflow =
      "hidden";

    window.addEventListener(
      "keydown",
      handleKeyDown
    );

    return () => {
      document.body.style.overflow =
        previousOverflow;

      window.removeEventListener(
        "keydown",
        handleKeyDown
      );
    };
  }, [
    open,
    onClose,
    closeDisabled,
  ]);

  if (!open) {
    return null;
  }

  function requestClose() {
    if (closeDisabled) {
      return;
    }

    onClose?.();
  }

  return (
    <div
      className="modal-backdrop"
      onMouseDown={requestClose}
    >
      <section
        className={[
          "detail-modal",
          `size-${size}`,
        ].join(" ")}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={
          description
            ? descriptionId
            : undefined
        }
        aria-busy={
          closeDisabled
            ? "true"
            : undefined
        }
        onMouseDown={(event) =>
          event.stopPropagation()
        }
      >
        <header className="modal-header">
          <div>
            <h2
              id={titleId}
              className="modal-title"
            >
              {title}
            </h2>

            {description && (
              <p
                id={descriptionId}
                className="modal-description"
              >
                {description}
              </p>
            )}
          </div>

          <button
            type="button"
            className="modal-close"
            onClick={requestClose}
            disabled={closeDisabled}
            aria-label={
              closeDisabled
                ? "작업 진행 중에는 창을 닫을 수 없습니다."
                : "상세 창 닫기"
            }
          >
            ×
          </button>
        </header>

        <div className="modal-content">
          {children}
        </div>

        {footer && (
          <footer className="modal-footer">
            {footer}
          </footer>
        )}
      </section>
    </div>
  );
}
