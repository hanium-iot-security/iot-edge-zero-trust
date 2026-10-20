import { useId, useRef, useState } from "react";
import {
  adjacentMonth, calendarDays, currentKstInput,
  dateTimeInputLabel, dateTimeInputValue, parseDateTimeInput,
} from "../utils/dateTimeInput";
import "../styles/components/DateTimePicker.scss";

export default function DateTimePicker({ id, label, value, onChange, withSeconds = false, disabled = false }) {
  const generatedId = useId();
  const inputId = id || `date-time-${generatedId}`;
  const dialogRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(null);
  const [month, setMonth] = useState("");
  const [error, setError] = useState("");

  function show() {
    const next = parseDateTimeInput(value) || parseDateTimeInput(currentKstInput(withSeconds));
    setDraft(next);
    setMonth(next.date.slice(0, 7));
    setError("");
    setOpen(true);
    dialogRef.current.showModal();
  }

  function close() {
    dialogRef.current.close();
    setOpen(false);
  }

  function apply() {
    const next = dateTimeInputValue(draft, withSeconds);
    if (!next) {
      setError("유효한 날짜와 시간을 입력해 주세요.");
      return;
    }
    onChange(next);
    close();
  }

  function update(field, next) {
    setDraft((previous) => ({ ...previous, [field]: next }));
    setError("");
  }

  const monthLabel = month ? `${Number(month.slice(0, 4))}년 ${Number(month.slice(5))}월` : "";

  return (
    <div className="date-time-picker">
      <button
        type="button" id={inputId} className="date-time-trigger"
        aria-label={`${label}: ${dateTimeInputLabel(value, withSeconds)}`}
        aria-haspopup="dialog" aria-expanded={open} aria-controls={`${inputId}-dialog`}
        disabled={disabled} onClick={show}
      >
        <span>{dateTimeInputLabel(value, withSeconds)}</span>
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true">
          <rect x="3" y="5" width="18" height="16" rx="2" />
          <path d="M7 2v6m10-6v6M3 11h18" />
        </svg>
      </button>
      <dialog
        ref={dialogRef} id={`${inputId}-dialog`} className="date-time-dialog"
        aria-labelledby={`${inputId}-title`}
        onClose={() => setOpen(false)}
        onCancel={() => setOpen(false)}
        onClick={(event) => { if (event.target === event.currentTarget) close(); }}
        onKeyDown={(event) => {
          event.stopPropagation();
          // Time fields belong to this picker, not the surrounding traffic-query form.
          if (event.key === "Enter" && event.target.tagName === "INPUT") {
            event.preventDefault();
            apply();
          }
        }}
      >
        {draft && (
          <div className="date-time-content">
            <h3 id={`${inputId}-title`}>{label} 선택</h3>
            <div className="date-time-month">
              <button type="button" aria-label="이전 달" disabled={month === "0001-01"} onClick={() => setMonth(adjacentMonth(month, -1))}>‹</button>
              <strong aria-live="polite">{monthLabel}</strong>
              <button type="button" aria-label="다음 달" disabled={month === "9999-12"} onClick={() => setMonth(adjacentMonth(month, 1))}>›</button>
            </div>
            <div className="date-time-calendar" role="group" aria-label={`${monthLabel} 날짜`}>
              {["일", "월", "화", "수", "목", "금", "토"].map((day) => <span className="date-time-weekday" key={day} aria-hidden="true">{day}</span>)}
              {calendarDays(month).map((date, index) => date ? (
                <button
                  key={date} type="button" className="date-time-day"
                  aria-label={`${date} 날짜`} aria-pressed={draft.date === date}
                  onClick={() => update("date", date)}
                >{Number(date.slice(-2))}</button>
              ) : <span key={`empty-${index}`} aria-hidden="true" />)}
            </div>
            <div className={`date-time-fields${withSeconds ? " has-seconds" : ""}`}>
              <label htmlFor={`${inputId}-period`}>오전·오후
                <select id={`${inputId}-period`} value={draft.period} onChange={(event) => update("period", event.target.value)}>
                  <option value="AM">오전</option><option value="PM">오후</option>
                </select>
              </label>
              <label htmlFor={`${inputId}-hour`}>시
                <input id={`${inputId}-hour`} type="number" min="1" max="12" step="1" value={draft.hour} onChange={(event) => update("hour", event.target.value)} />
              </label>
              <label htmlFor={`${inputId}-minute`}>분
                <input id={`${inputId}-minute`} type="number" min="0" max="59" step="1" value={draft.minute} onChange={(event) => update("minute", event.target.value)} />
              </label>
              {withSeconds && <label htmlFor={`${inputId}-second`}>초
                <input id={`${inputId}-second`} type="number" min="0" max="59" step="1" value={draft.second} onChange={(event) => update("second", event.target.value)} />
              </label>}
            </div>
            <p className="date-time-caption">{draft.date} · 한국 시간(KST)</p>
            {error && <p className="date-time-error" role="alert">{error}</p>}
            <div className="date-time-actions">
              <button type="button" className="date-time-clear" onClick={() => { onChange(""); close(); }}>지우기</button>
              <button type="button" onClick={close}>취소</button>
              <button type="button" className="date-time-apply" onClick={apply}>적용</button>
            </div>
          </div>
        )}
      </dialog>
    </div>
  );
}
