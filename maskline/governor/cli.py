"""``maskline governor ...`` command-line interface.

The CLI is a thin control plane over :class:`Governor`.  Job submission takes
the exact same masking command an operator already uses (for example
``maskline run --dataset x --policy y``) after a ``--`` separator, so existing
task commands need no modification.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from ..config import Paths
from .config import load_config, parse_overrides
from .daemon import Governor, is_daemon_running, read_status
from .errors import GovernorError, JobControlError, QuotaConfigError


def _common_governor_flags() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config", default=None,
        help="governor YAML config (built-in defaults are used when omitted)",
    )
    common.add_argument(
        "--workspace", default=None,
        help="runtime workspace directory (default: current directory / MASKLINE_HOME)",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common_governor_flags()
    parser = argparse.ArgumentParser(
        prog="maskline governor",
        parents=[common],
        description="Offline quota governance and FIFO scheduling for masking tasks",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser(
        "start", parents=[common],
        help="run the governor daemon in the foreground",
    )
    sub.add_parser(
        "status", parents=[common], help="show whether the daemon is running"
    )

    submit = sub.add_parser(
        "submit", parents=[common],
        help="queue a masking command under governance",
    )
    submit.add_argument("--name", default=None, help="stable name for per-task quota pins")
    submit.add_argument(
        "--quota", action="append", default=[],
        help="key=value override; repeatable. keys: cpu_max_percent, "
             "memory_max_mb, max_runtime_seconds",
    )
    submit.add_argument(
        "--env", action="append", default=[],
        help="KEY=VALUE environment variable passed to the worker; repeatable",
    )
    submit.add_argument(
        "--resume-mode", choices=("auto", "maskline", "generic"), default="auto",
        help="how a paused slice is restarted; 'auto' detects native maskline "
             "commands, 'generic' replays the command verbatim (default: auto)",
    )
    submit.add_argument(
        "command", nargs=argparse.REMAINDER,
        help="the existing masking command after '--', e.g. -- maskline run ...",
    )

    ps = sub.add_parser(
        "ps", parents=[common], help="list jobs with live resource/quota usage"
    )
    ps.add_argument("--all", action="store_true", help="include terminal jobs")
    ps.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    cancel = sub.add_parser(
        "cancel", parents=[common], help="cancel a queued or active job"
    )
    cancel.add_argument("job_id")

    quota = sub.add_parser(
        "quota", parents=[common], help="inspect or adjust quotas (audited)"
    )
    quota.add_argument("--global", dest="global_scope", action="store_true")
    quota.add_argument("--job", dest="job_ref", default=None)
    quota.add_argument("--set", action="append", default=[])
    quota.add_argument("--json", action="store_true")

    sub.add_parser(
        "reload", parents=[common], help="re-read the governor config file"
    )

    return parser


def _paths(args: argparse.Namespace) -> Paths:
    return Paths.for_workspace(getattr(args, "workspace", None))


def _config(args: argparse.Namespace):
    return load_config(getattr(args, "config", None))


def _parse_env(items: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise QuotaConfigError(f"--env must be KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise QuotaConfigError("--env variable name must not be empty")
        env[key] = value
    return env


def _strip_separator(command: list[str]) -> list[str]:
    if command and command[0] == "--":
        return command[1:]
    return command


def _print_ps_table(snapshot: dict[str, Any], include_terminal: bool) -> None:
    system = snapshot["system"]
    print(
        f"daemon_pid={snapshot['daemon_pid']} "
        f"slots={system['concurrency_in_use']}/{system['max_concurrency']} "
        f"mem_avail={system['available_memory_mb']:.0f}MB/"
        f"{system['total_memory_mb']:.0f}MB "
        f"active={snapshot['active_count']} queued={snapshot['queued_count']}"
    )
    for job in snapshot["jobs"]:
        if not include_terminal and job["state"] in ("completed", "failed", "cancelled"):
            continue
        print(
            f"{job['job_id']}  {job['state']:<9} {job['name']:<18} "
            f"cpu={job['last_cpu_percent']:6.1f}%/{job['quota']['cpu_max_percent']}% "
            f"rss={job['last_rss_mb']:7.1f}MB/{job['quota']['memory_max_mb']}MB "
            f"run={job['runtime_seconds']:7.1f}s/"
            f"{job['quota']['max_runtime_seconds']}s "
            f"att={job['attempt']} pid={job['pid']} src={job['quota_source']}"
        )
        if job["state"] in ("failed",) and job["last_error"]:
            print(f"    error: {job['last_error'][:160]}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = _config(args)
        paths = _paths(args)
        if args.action == "start":
            paths.ensure_runtime_dirs()
            with Governor(paths, config) as governor:
                governor.serve_forever()
            return 0

        if args.action == "status":
            running = is_daemon_running(paths)
            print("running" if running else "stopped")
            if running:
                print(f"pid_file={paths.governor_pid_file}")
            return 0 if running else 1

        if args.action == "submit":
            command = _strip_separator(args.command)
            if not command:
                raise JobControlError(
                    "submit requires a command after '--', "
                    "e.g. maskline governor submit -- maskline run --dataset ..."
                )
            overrides = parse_overrides(args.quota)
            with Governor(paths, config) as governor:
                result = governor.submit(
                    command,
                    name=args.name,
                    overrides=overrides,
                    extra_env=_parse_env(args.env),
                    resume_mode=None if args.resume_mode == "auto"
                    else args.resume_mode,
                )
            print(
                f"submitted job={result.job_id} state={result.state} "
                f"quota_source={result.quota_source}"
            )
            print(
                f"  cpu_max_percent={result.quota.cpu_max_percent} "
                f"memory_max_mb={result.quota.memory_max_mb} "
                f"max_runtime_seconds={result.quota.max_runtime_seconds}"
            )
            if not is_daemon_running(paths):
                print("note: governor daemon is stopped; start it to begin scheduling")
            return 0

        if args.action == "ps":
            snapshot = read_status(paths, config)
            if args.json:
                print(json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False))
            else:
                _print_ps_table(snapshot, include_terminal=args.all)
            return 0

        if args.action == "cancel":
            with Governor(paths, config) as governor:
                record = governor.cancel(args.job_id)
            print(f"cancelled {record.job_id} state={record.state}")
            return 0

        if args.action == "quota":
            changes = parse_overrides(args.set)
            with Governor(paths, config) as governor:
                if not changes:
                    effective = governor.effective_config()
                    print(json.dumps(effective.as_dict(), indent=2,
                                     sort_keys=True, ensure_ascii=False))
                    return 0
                if args.global_scope:
                    governor.update_quota("<global>", changes, scope="global")
                    print(f"global defaults updated: {changes}")
                else:
                    if not args.job_ref:
                        raise JobControlError(
                            "use --global for default quotas or --job <id/name>"
                        )
                    record = governor.update_quota(args.job_ref, changes, scope="job")
                    print(f"job {record.job_id} quota updated: {record.quota()}")
            return 0

        if args.action == "reload":
            with Governor(paths, config) as governor:
                reloaded = governor.reload_config(args.config)
            print(f"config reloaded from {reloaded.source_path}")
            return 0

        parser.error(f"unknown action {args.action!r}")
        return 2
    except (GovernorError, QuotaConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
