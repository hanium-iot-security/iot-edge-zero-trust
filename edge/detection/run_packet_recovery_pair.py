"""Plan/apply/status/verify for a detached one-shot Packet pair manager."""
import argparse
import json
import os
import signal

from edge.detection import packet_checkpoint_pair_manager as manager


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal-supervisor", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--internal-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--plan-file")
    parser.add_argument("--worker-token", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command")
    plan = commands.add_parser("plan")
    for field in ("pair-plan-file", "db-path", "artifact-dir", "plan-output"):
        plan.add_argument("--" + field, required=True)
    for name in ("apply", "status", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--plan-file", required=True)
        if name == "apply":
            command.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    try:
        if args.internal_supervisor or args.internal_worker:
            if os.name != "posix":
                raise manager.Error("internal manager requires Linux")
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            if args.internal_supervisor:
                def interrupted(signum, frame):
                    raise InterruptedError("supervisor interrupted")
                signal.signal(signal.SIGTERM, interrupted)
            result = manager.supervise(args.plan_file) if args.internal_supervisor else manager.worker(args.plan_file, args.worker_token)
        elif args.command == "plan":
            result = manager.create_plan(pair_plan_file=args.pair_plan_file, db_path=args.db_path,
                                         artifact_dir=args.artifact_dir, plan_output=args.plan_output)
        elif args.command == "apply":
            result = manager.apply(plan_file=args.plan_file, confirm=args.confirm)
        elif args.command == "status":
            result = manager.status(plan_file=args.plan_file)
        elif args.command == "verify":
            result = manager.verify(plan_file=args.plan_file)
        else:
            parser.error("a command is required")
    except Exception as error:
        result = {"operation_status": "HOLD", "database_committed": None, "error": type(error).__name__}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if args.command == "plan":
        return 0 if result.get("can_execute") else 2
    if result.get("operation_status") in manager.pair.COMPLETE_STATUSES or result.get("phase") in manager.pair.COMPLETE_STATUSES:
        return 0
    return 2 if result.get("database_committed") is False else 3


if __name__ == "__main__":
    raise SystemExit(main())
