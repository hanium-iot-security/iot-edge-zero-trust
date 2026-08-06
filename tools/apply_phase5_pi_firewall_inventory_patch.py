"""Apply the final read-only iptables inventory gate and Runbook note.

The script is fail-closed: every expected anchor must occur exactly once before
any file is written. It removes itself after a successful application.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLEANUP = ROOT / "edge" / "scenarios" / "cleanup.py"
GUIDE = ROOT / "docs" / "phase5-scenario-runner-execution-guide.md"
SELF = Path(__file__).resolve()


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"HOLD: {label} expected once, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    cleanup_text = CLEANUP.read_text(encoding="utf-8")
    guide_text = GUIDE.read_text(encoding="utf-8")

    process_anchor = """def _active_firewall_rows(\n"""
    inventory_helper = """def _list_project_firewall_rules(source_ip: str | None) -> list[str]:
    \"\"\"기존 root Wrapper의 list 명령으로 실제 프로젝트 Rule을 읽기 전용 조회한다.\"\"\"

    try:
        completed = subprocess.run(
            [
                settings.firewall_sudo_path,
                "-n",
                settings.firewall_wrapper_path,
                "list",
            ],
            capture_output=True,
            text=True,
            timeout=settings.firewall_command_timeout_seconds,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"firewall_inventory_error: {exc}"]

    if completed.returncode != 0:
        reason = completed.stderr.strip() or f"exit_code={completed.returncode}"
        return [f"firewall_inventory_error: {reason}"]

    project_rules = [
        line.strip()
        for line in completed.stdout.splitlines()
        if "hanium-firewall:" in line
    ]
    if source_ip:
        project_rules = [
            line
            for line in project_rules
            if f"-s {source_ip} " in f"{line} "
            or f"-s {source_ip}/32 " in f"{line} "
        ]
    return project_rules


""" + process_anchor
    cleanup_text = replace_once(
        cleanup_text,
        process_anchor,
        inventory_helper,
        label="firewall inventory helper insertion",
    )

    baseline_anchor = """    conflicts = _find_conflicting_processes()\n"""
    baseline_replacement = """    actual_firewall_rules = _list_project_firewall_rules(context.source_ip)
    inventory_errors = [
        item for item in actual_firewall_rules if item.startswith("firewall_inventory_error:")
    ]
    if inventory_errors:
        return False, inventory_errors[0]
    if actual_firewall_rules:
        return False, "active_iptables_rule: " + " | ".join(actual_firewall_rules)

    conflicts = _find_conflicting_processes()
"""
    cleanup_text = replace_once(
        cleanup_text,
        baseline_anchor,
        baseline_replacement,
        label="baseline actual firewall gate",
    )

    guide_anchor = """두 옵션은 `module.submodule:function_name` 형식으로 실제 훅 함수의 위치를 지정한다. 예:\n\n```bash\n"""
    guide_replacement = """두 옵션은 `module.submodule:function_name` 형식으로 실제 훅 함수의 위치를 지정한다.
Pi에서는 상대경로 기본값이 다른 DB를 가리키지 않도록 운영 DB의 절대경로를 먼저 명시한다.

```bash
export DATABASE_URL="sqlite:////home/pi/iot-edge-zero-trust/backend/data/iot_security.db"

"""
    guide_text = replace_once(
        guide_text,
        guide_anchor,
        guide_replacement,
        label="absolute DATABASE_URL guide",
    )

    safety_anchor = """- 대상 Device 또는 Source IP에 `PENDING`/`APPLIED` Firewall Rule이 있으면 공격을 시작하지 않는다.\n"""
    safety_replacement = safety_anchor + (
        "- DB에 활성 Row가 없더라도 실제 iptables에 대상 Source IP의 `hanium-firewall:` Rule이 남아 있으면 공격을 시작하지 않는다. Baseline은 기존 root Wrapper의 `list` 명령으로 읽기만 하며 Rule을 삭제하지 않는다.\n"
    )
    guide_text = replace_once(
        guide_text,
        safety_anchor,
        safety_replacement,
        label="actual iptables safety note",
    )

    CLEANUP.write_text(cleanup_text, encoding="utf-8", newline="\n")
    GUIDE.write_text(guide_text, encoding="utf-8", newline="\n")
    SELF.unlink()
    print("PHASE5_PI_FIREWALL_INVENTORY_PATCH=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
