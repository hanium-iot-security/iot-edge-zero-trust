import {
  useId,
  useLayoutEffect,
  useRef,
} from "react";

import "../styles/components/DetailModal.scss";

const modalStates = new WeakMap();

function focusableElements(dialog) {
  return Array.from(dialog.querySelectorAll(
    'button, a[href], input:not([type="hidden"]), select, textarea, summary, [tabindex], [contenteditable="true"]'
  )).filter((element) =>
    (element.tabIndex >= 0 || (element.isContentEditable && !element.hasAttribute("tabindex"))) &&
    !element.matches(":disabled") &&
    !element.closest('[hidden], [inert], [aria-hidden="true"]') &&
    !["hidden", "collapse"].includes(dialog.ownerDocument.defaultView.getComputedStyle(element).visibility) &&
    element.getClientRects().length > 0
  ).sort((a, b) => (a.tabIndex > 0 ? a.tabIndex : Infinity) - (b.tabIndex > 0 ? b.tabIndex : Infinity));
}

function focusInside(entry) {
  const controls = focusableElements(entry.dialog);
  const target = controls.includes(entry.lastFocus) ? entry.lastFocus : controls[0] || entry.dialog;
  target.focus({ preventScroll: true });
}

function updateModalLayers(state) {
  state.stack.forEach((entry, index) => {
    entry.backdrop.style.zIndex = String(1001 + index);
  });
}

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
  const dialogRef = useRef(null);
  const closeRef = useRef({ onClose, closeDisabled });
  closeRef.current = { onClose, closeDisabled };

  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    if (!open || !dialog) {
      return undefined;
    }

    const ownerDocument = dialog.ownerDocument;
    let state = modalStates.get(ownerDocument);
    if (!state) {
      state = { stack: [], overflow: ownerDocument.body.style.overflow };
      modalStates.set(ownerDocument, state);
    }
    const backdrop = dialog.parentElement;
    const previousZIndex = backdrop.style.zIndex;
    // Child layout effects can run first. Register a later parent beneath its
    // existing descendants, retaining their original external opener chain.
    const descendantIndex = state.stack.findIndex((active) => dialog.contains(active.dialog));
    const descendant = descendantIndex < 0 ? null : state.stack[descendantIndex];
    let returnFocus = ownerDocument.activeElement;
    if (descendant && dialog.contains(returnFocus)) {
      for (let prior = descendant; prior; prior = prior.previous) {
        if (!dialog.contains(prior.returnFocus)) {
          returnFocus = prior.returnFocus;
          break;
        }
      }
    }
    const entry = { dialog, backdrop, returnFocus, previous: descendant ? descendant.previous : state.stack.at(-1) };
    if (descendant) {
      state.stack.splice(descendantIndex, 0, entry);
      descendant.previous = entry;
    } else {
      state.stack.push(entry);
    }
    updateModalLayers(state);
    ownerDocument.body.style.overflow = "hidden";
    const isTop = () => state.stack.at(-1) === entry;

    function handleKeyDown(event) {
      if (!isTop() || event.defaultPrevented) {
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (!closeRef.current.closeDisabled) {
          closeRef.current.onClose?.();
        }
      } else if (event.key === "Tab") {
        const controls = focusableElements(dialog);
        const active = ownerDocument.activeElement;
        const first = controls[0];
        const last = controls.at(-1);
        if (!controls.length) {
          event.preventDefault();
          dialog.focus({ preventScroll: true });
        } else if (!controls.includes(active) ||
            (event.shiftKey ? active === first : active === last)) {
          event.preventDefault();
          (event.shiftKey ? last : first).focus({ preventScroll: true });
        }
      }
    }

    function handleFocusIn(event) {
      if (!isTop()) {
        return;
      }
      if (dialog.contains(event.target)) {
        entry.lastFocus = event.target;
      } else {
        focusInside(entry);
      }
    }

    ownerDocument.addEventListener("keydown", handleKeyDown);
    ownerDocument.addEventListener("focusin", handleFocusIn);
    focusInside(state.stack.at(-1));

    return () => {
      ownerDocument.removeEventListener("keydown", handleKeyDown);
      ownerDocument.removeEventListener("focusin", handleFocusIn);
      const wasTop = isTop();
      state.stack.splice(state.stack.indexOf(entry), 1);
      backdrop.style.zIndex = previousZIndex;
      updateModalLayers(state);
      if (!state.stack.length) {
        ownerDocument.body.style.overflow = state.overflow;
        modalStates.delete(ownerDocument);
      }
      if (wasTop) {
        const remaining = state.stack.at(-1);
        // StrictMode can clean up dialog effects without removing their DOM.
        // Follow the opener chain past controls in those retired dialogs.
        const retiredDialogs = [];
        for (let owner = entry; owner; owner = owner.previous) {
          if (!state.stack.includes(owner)) retiredDialogs.push(owner.dialog);
        }
        let previous = entry;
        while (previous) {
          const target = previous.returnFocus;
          if (target?.isConnected && typeof target.focus === "function" &&
              !retiredDialogs.some((retired) => retired.contains(target)) &&
              (!remaining || remaining.dialog.contains(target))) {
            target.focus({ preventScroll: true });
            if (ownerDocument.activeElement === target) {
              return;
            }
          }
          previous = previous.previous;
        }
        if (remaining) {
          focusInside(remaining);
        }
      }
    };
  }, [open]);

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
        ref={dialogRef}
        tabIndex={-1}
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
