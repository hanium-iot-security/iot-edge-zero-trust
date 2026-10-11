"""Administrator CLI for approved sequential Rule/IF live resume."""
from __future__ import annotations

import argparse
from contextlib import closing
import json

from edge.detection import packet_checkpoint_pair_recovery as pair


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    dry_run = commands.add_parser("dry-run")
    for name in ("db-path", "repository-root", "current-session-id", "target-session-id",
                 "approved-by", "reason", "plan-output"):
        dry_run.add_argument("--" + name, required=True)
    dry_run.add_argument("--mode", choices=(pair.core.LIVE_RESUME_MODE, pair.core.BOUNDED_REPLAY_MODE),
                         default=pair.core.LIVE_RESUME_MODE)
    dry_run.add_argument("--allow-failed-current-session", action="store_true",
                         help="approve only the existing uncaptured LATE_CAPTURE tail live-resume contract")
    for name in ("execute", "status", "resume"):
        command = commands.add_parser(name)
        for field in ("plan-file", "db-path", "artifact-dir"):
            command.add_argument("--" + field, required=True)
        if name != "status":
            command.add_argument("--confirm", required=True)
            command.add_argument("--confirm-skip-processable")
    return parser


def _failure_payload(args, error):
    # An exception, missing stdout or artifact is never proof that COMMIT did not happen.
    payload = {"ok": False, "database_committed": None, "operation_status": "HOLD",
               "error": str(error)}
    if args.command == "dry-run":
        return dict(payload, database_committed=False)
    try:
        _, plan = pair._load_pair(args.plan_file)
        database = pair.core.require_plan_database_path(plan, args.db_path)
        with closing(pair._read_db(database)) as db:
            committed = {child["detector"]: pair.repository.get_recovery_audit(
                db, child["child_operation_id"]) is not None for child in plan["children"]}
        payload.update(pair_id=plan["pair_id"], database_committed=any(committed.values()),
                       children={name: "COMMITTED_UNVERIFIED" if applied else "PENDING_UNVERIFIED"
                                 for name, applied in committed.items()})
    except Exception:
        pass
    return payload


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        fields = vars(args).copy()
        fields.pop("command")
        if args.command == "dry-run":
            payload = pair.inspect_pair(**fields)
        elif args.command == "status":
            payload = pair.status_pair(**fields)
        else:
            payload = pair.execute_pair(**fields, resume=args.command == "resume")
    except Exception as exc:
        payload = _failure_payload(args, exc)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 2 if payload["database_committed"] is False else 3
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if args.command == "dry-run":
        return 0 if payload["can_execute"] else 2
    if payload["operation_status"] in pair.COMPLETE_STATUSES:
        return 0
    return 2 if payload["database_committed"] is False else 3


if __name__ == "__main__":
    raise SystemExit(main())
