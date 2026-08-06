"""Apply the reviewed Phase 5 ScenarioHookContext wiring.

This one-shot maintainer script performs exact, fail-closed replacements against
run_scenario.py and the execution guide. Both files are fully preflighted in
memory before either file is written. The script deletes itself only after a
successful atomic application.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "edge" / "scenarios" / "run_scenario.py"
GUIDE = ROOT / "docs" / "phase5-scenario-runner-execution-guide.md"
SELF = Path(__file__).resolve()


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"HOLD: {label} expected exactly once, found {count}. "
            "No file was written. Compare the branch with develop first."
        )
    return text.replace(old, new, 1)


def patched_runner_text(text: str) -> str:
    text = replace_once(
        text,
        "import hashlib\nimport json\nimport re\n",
        "import hashlib\nimport inspect\nimport json\nimport re\n",
        label="inspect import",
    )

    text = replace_once(
        text,
        "from edge.scenarios.cleanup import (\n"
        "    BaselineCheck,\n"
        "    CleanupHook,\n"
        "    default_baseline_check,\n"
        "    default_cleanup_hook,\n"
        ")\n",
        "from edge.scenarios.cleanup import (\n"
        "    BaselineCheck,\n"
        "    CleanupHook,\n"
        "    ScenarioHookContext,\n"
        "    default_baseline_check,\n"
        "    default_cleanup_hook,\n"
        ")\n",
        label="ScenarioHookContext import",
    )

    anchor = (
        'AWAITING_SESSION_CORRELATION = "AWAITING_SESSION_CORRELATION"\n'
        'DRY_RUN_EXCLUSION_REASON = "DRY_RUN"\n\n'
    )
    helper = anchor + (
        "def _call_scenario_hook(\n"
        "    hook: BaselineCheck | CleanupHook,\n"
        "    context: ScenarioHookContext,\n"
        ") -> tuple[bool, str | None]:\n"
        "    \"\"\"Context-aware Hook을 호출한다.\n\n"
        "    기존 Local 단위 테스트의 no-arg 더미 Hook만 한시적으로 호환한다.\n"
        "    실제 Pi Hook은 반드시 ScenarioHookContext를 받아야 한다.\n"
        "    \"\"\"\n"
        "    try:\n"
        "        parameters = inspect.signature(hook).parameters\n"
        "    except (TypeError, ValueError):\n"
        "        parameters = {\"context\": object()}\n"
        "    if not parameters:\n"
        "        return hook()  # type: ignore[call-arg]\n"
        "    return hook(context)\n\n"
    )
    text = replace_once(text, anchor, helper, label="hook adapter")

    insertion_anchor = (
        "        args = self._build_args(\n"
        "            defn, target_device_id=target_device_id, target_host=target_host, extra_args=extra_args\n"
        "        )\n\n"
        "        command = self._build_command(defn, args)\n"
    )
    insertion = (
        "        hook_context = ScenarioHookContext(\n"
        "            run_id=run_id,\n"
        "            scenario_id=scenario_id,\n"
        "            session_id=session_id,\n"
        "            target_device_id=target_device_id,\n"
        "            source_ip=source_ip,\n"
        "            target_host=target_host,\n"
        "            evaluation_scope=evaluation_scope.value,\n"
        "            execution_node=self.execution_node,\n"
        "        )\n\n"
        "        args = self._build_args(\n"
        "            defn, target_device_id=target_device_id, target_host=target_host, extra_args=extra_args\n"
        "        )\n\n"
        "        command = self._build_command(defn, args)\n"
    )
    text = replace_once(text, insertion_anchor, insertion, label="hook context creation")

    text = replace_once(
        text,
        "            baseline_ok, baseline_reason = self.baseline_check()\n",
        "            baseline_ok, baseline_reason = _call_scenario_hook(\n"
        "                self.baseline_check, hook_context\n"
        "            )\n",
        label="baseline context call",
    )

    text = replace_once(
        text,
        "            cleanup_ok, cleanup_reason = self.cleanup_hook()\n",
        "            cleanup_ok, cleanup_reason = _call_scenario_hook(\n"
        "                self.cleanup_hook, hook_context\n"
        "            )\n",
        label="cleanup context call",
    )
    return text


def patched_guide_text(text: str) -> str:
    old = (
        "> `[TODO: 실기기 검증 필요]` `edge/scenarios/cleanup.py` 하단에 주석으로만 남아있는 "
        "`pi_baseline_check`/`pi_cleanup_hook` 예시 뼈대를 실제 구현으로 채우고 주석을 해제해야 위 명령이 동작한다. "
        "뼈대를 채우지 않은 상태에서 위 두 옵션에 존재하지 않는 함수를 지정하면 `모듈 경로 형식이 올바르지 않습니다` "
        "또는 `함수가 없습니다` 에러로 명확히 거부된다.\n"
    )
    new = (
        "> `edge.scenarios.cleanup:pi_baseline_check`와 `pi_cleanup_hook`은 동일한 "
        "`ScenarioHookContext`를 받는다. Baseline은 SQLite read-only 조회, 필수 Runtime, "
        "Capture Session, 활성 Firewall 요청, 충돌 프로세스를 확인한다. Cleanup은 잔여 공격·수동 실행 "
        "프로세스만 확인하며 DB·Trust·Device·Firewall·iptables 상태를 변경하지 않는다.\n"
    )
    text = replace_once(text, old, new, label="guide TODO replacement")

    marker = "## 2. Dry-run과 반복 실행 방법\n"
    section = (
        "## 1.1 Pi Hook 최소 안전 계약\n\n"
        "- `--session-id`가 있으면 해당 `packet_capture_sessions` Row가 `RUNNING`이고 "
        "`ended_at IS NULL`이어야 하며 `packet-capture.service`도 `active`여야 한다.\n"
        "- `--session-id`가 없는 Detection-only 실행에서는 의도하지 않은 수집을 막기 위해 "
        "`packet-capture.service`가 `inactive`여야 한다.\n"
        "- 대상 Device가 있으면 DB에 존재하고 `devices.status=normal`이어야 한다.\n"
        "- 대상 Device 또는 Source IP에 `PENDING`/`APPLIED` Firewall Rule이 있으면 공격을 시작하지 않는다.\n"
        "- 공격 종료 직후 Cleanup은 잔여 Process만 확인한다. Detection·Trust·Firewall·실제 Block "
        "Observation 전에 자동 Release나 Trust Recovery를 수행하지 않는다.\n"
        "- 복구가 필요하면 증적 확인 후 기존 승인형 Firewall Release, Baseline Recovery, "
        "Trust Score Compensation 절차를 별도로 사용한다.\n\n"
    )
    return replace_once(text, marker, section + marker, label="guide safety section")


def main() -> int:
    original_runner = RUNNER.read_text(encoding="utf-8")
    original_guide = GUIDE.read_text(encoding="utf-8")

    # Fail-closed preflight: no filesystem writes occur before both transforms pass.
    new_runner = patched_runner_text(original_runner)
    new_guide = patched_guide_text(original_guide)

    RUNNER.write_text(new_runner, encoding="utf-8", newline="\n")
    GUIDE.write_text(new_guide, encoding="utf-8", newline="\n")
    SELF.unlink()
    print("PHASE5_PI_SCENARIO_HOOK_CONTEXT_PATCH=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
