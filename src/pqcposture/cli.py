"""Command line interface.

Exit codes are part of the interface Phase 3 depends on:
  0  scan completed, thresholds met (or none set)
  1  scan completed, a target fell below --min-grade / --min-score
  2  usage error
  3  no usable OpenSSL
"""

from __future__ import annotations

import argparse
import sys

from . import openssl as ossl
from . import report as reporting
from .models import GroupKind, kind_of
from .scanner import Scanner

GRADE_RANK = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}


def parse_target(raw: str) -> tuple[str, int, str | None]:
    """Accepts host, host:port, or host:port@sni."""
    raw = raw.strip()
    sni = None
    if "@" in raw:
        raw, _, sni = raw.partition("@")
    if raw.startswith("["):  # bracketed IPv6
        close = raw.index("]")
        host = raw[1:close]
        rest = raw[close + 1:]
        port = int(rest[1:]) if rest.startswith(":") else 443
        return host, port, sni
    if raw.count(":") == 1:
        host, _, port_s = raw.partition(":")
        return host, int(port_s), sni
    return raw, 443, sni


def load_targets(path: str) -> list[tuple[str, int, str | None]]:
    targets = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(parse_target(line))
    return targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-posture",
        description="Measure TLS post-quantum key exchange posture.")
    parser.add_argument("targets", nargs="*",
                        help="host, host:port, or host:port@sni")
    parser.add_argument("-f", "--targets-file",
                        help="file with one target per line, # comments allowed")
    parser.add_argument("--openssl", help="path to an OpenSSL 3.5+ binary")
    parser.add_argument("--allow-old-openssl", action="store_true",
                        help="run with a pre-3.5 client; PQ groups will be "
                             "reported as client-unsupported, not absent")
    parser.add_argument("--json", metavar="PATH",
                        help="write the JSON report here ('-' for stdout)")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the human-readable report")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show every probe and informational finding")
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--concurrency", type=int, default=8,
                        help="targets scanned in parallel; probes within one "
                             "target always run serially")
    parser.add_argument("--no-legacy-tls", action="store_true",
                        help="skip TLS 1.0/1.1 probes")
    parser.add_argument("--draft-groups", action="store_true",
                        help="also probe pre-standard Kyber names, if the "
                             "local provider offers them")
    parser.add_argument("-i", "--inventory", metavar="PATH",
                        help="Phase 1 service inventory JSON (frontend/VIP + "
                             "backends). Produces observation evidence and a "
                             "topology assessment, not a score.")
    parser.add_argument("--repeat", type=int,
                        help="override the repeat count for every endpoint in "
                             "the inventory")
    parser.add_argument("--trace", action="store_true",
                        help="use -trace to detect HelloRetryRequest")
    parser.add_argument("--min-grade", choices=list(GRADE_RANK),
                        help="exit 1 if any target grades below this")
    parser.add_argument("--min-score", type=int,
                        help="exit 1 if any target scores below this")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    targets = [parse_target(t) for t in args.targets]
    if args.targets_file:
        targets += load_targets(args.targets_file)
    if not targets and not args.inventory:
        print("no targets given", file=sys.stderr)
        return 2

    try:
        info = ossl.discover(args.openssl,
                             require_minimum=not args.allow_old_openssl)
    except ossl.OpenSSLNotUsable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    hybrids = [g for g in info.groups if kind_of(g) == GroupKind.HYBRID]
    if not hybrids:
        print(f"warning: {info.version_string} cannot offer any hybrid group. "
              "Results will show PQ groups as client-unsupported, which is a "
              "statement about this scanner, not about the targets.",
              file=sys.stderr)

    if args.inventory:
        return _run_inventory(args, info)

    scanner = Scanner(
        info,
        timeout=args.timeout,
        concurrency=args.concurrency,
        include_legacy_tls=not args.no_legacy_tls,
        include_draft_groups=args.draft_groups,
        trace=args.trace,
        progress=(lambda msg: None) if args.quiet
        else (lambda msg: print(msg, file=sys.stderr)),
    )
    result = scanner.scan(targets)

    if not args.quiet:
        print(reporting.render(result, verbose=args.verbose))

    if args.json:
        blob = reporting.to_json(result)
        if args.json == "-":
            print(blob)
        else:
            with open(args.json, "w", encoding="utf-8") as handle:
                handle.write(blob + "\n")

    failed = []
    for target in result.targets:
        if args.min_grade and GRADE_RANK[target.grade] < GRADE_RANK[args.min_grade]:
            failed.append(f"{target.label} graded {target.grade}")
        elif args.min_score is not None and target.score < args.min_score:
            failed.append(f"{target.label} scored {target.score}")
    if failed:
        print("threshold not met: " + "; ".join(failed), file=sys.stderr)
        return 1
    return 0


def _run_inventory(args, info) -> int:
    """Phase 1: observation. No grades are emitted here by design."""
    from .inventory import InventoryError, load_inventory_file
    from .service import ServiceScanner

    try:
        services = load_inventory_file(args.inventory)
    except (InventoryError, ValueError, KeyError) as exc:
        print(f"inventory error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"cannot read inventory: {exc}", file=sys.stderr)
        return 2

    if args.repeat:
        for service in services:
            for endpoint in service.all_endpoints():
                endpoint.repeat = args.repeat

    scanner = ServiceScanner(
        info,
        timeout=args.timeout,
        concurrency=args.concurrency,
        include_draft_groups=args.draft_groups,
        trace=args.trace,
        progress=(lambda msg: None) if args.quiet
        else (lambda msg: print(msg, file=sys.stderr)),
    )
    results = scanner.scan_all(services)

    if not args.quiet:
        for result in results:
            print(reporting.render_service(result))
            print()

    if args.json:
        blob = reporting.services_to_json(
            results, openssl_version=info.version_string,
            client_groups=info.groups)
        if args.json == "-":
            print(blob)
        else:
            with open(args.json, "w", encoding="utf-8") as handle:
                handle.write(blob + "\n")

    # Phase 1 gates on nothing. A declared/observed conflict is reported, not
    # failed on: deciding what is acceptable is Phase 4's job.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
