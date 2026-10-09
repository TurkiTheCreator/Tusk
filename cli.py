import argparse
import json
import sys
from urllib.parse import urlparse

from rich.console import Console

from core.target import Target
from core.scanner import Scanner
from core.utils import resolve_host
from core.logger import Logger
from core.config.config_manager import ConfigManager, write_default_config
from scoring.cvss import calculate as calculate_cvss, CVSSError
from discovery.ports import TOP_PORTS
from discovery.analyzers.http_analyzer import HttpAnalyzer
from core.engine.rule_engine import RuleEngineError


console = Console()



def parse_ports(spec):
    """'1-1024,8080' -> sorted unique list; raises ValueError on bad input."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                raise ValueError(f"reversed range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be within 1-65535")
    return sorted(ports)


def parse_target(raw):
    """'https://host:8443/x' -> ('host', 8443); bare 'host' -> ('host', None)."""
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname, parsed.port
    return raw, None


def show_banner():

    banner = r"""
┌──────────────────── TUSK ACT 1 ────────────────────┐
│                                                     │
│          ★══════◎══════★                           │
│                                                     │
│    ________  _______ __ __                         │
│   /_  __/ / / / ___// //_/                         │
│    / / / / / /\__ \/ ,<                            │
│   / / / /_/ /___/ / /| |                           │
│  /_/  \____//____/_/ |_|                           │
│                                                     │
│             「Infinite Rotation」                   │
│                                                     │
│  User       : TurkiTheCreator                       │
│  Version    : 0.1                                  │
│                                                     │
│                                                     │
│   ★ Port Scanner                                   │
│   ★ Header Analysis                                │
│   ★ Technology Detection                           │
│   ★ CVE Lookup                                     │
│   ★ SSL Inspection                                 │
│   ★ Banner Grabbing                                │
│                                                     │
│  Status : READY                                    │
│                                                     │
│     CHUMIMI~IN                                      │
│                                                     │
└─────────────────────────────────────────────────────┘
"""

    print(banner)


def main():

    parser = argparse.ArgumentParser(
        prog="tusk",
        description="Tusk - Lightweight vulnerability scanner",
        epilog="""
Examples:

  tusk scan -u example.com

  tusk scan -u example.com -t 200

  tusk scan -u example.com -p 80,443

  tusk scan -u example.com --top-ports 100

  tusk scan -u example.com --full

  tusk scan -u example.com --full -o output.json
"""
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=["scan", "config"],
        help="Command to execute"
    )

    parser.add_argument(
        "config_action",
        nargs="?",
        choices=["init"],
        help="Config subcommand (e.g. init)"
    )

    parser.add_argument(
        "-u",
        "--url",
        "--target",
        dest="url",
        help="Target host or URL (e.g. example.com, ::1, https://host:8443/)"
    )

    # Note: these default to None so the layered ConfigManager (defaults ->
    # TOML file -> env vars -> CLI flags) can tell an explicit flag apart
    # from "not passed".
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=None,
        help="Number of threads"
    )

    parser.add_argument(
        "--port-timeout",
        type=float,
        default=None,
        help="Socket timeout for port scanning (seconds)"
    )

    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=None,
        help="Socket timeout for banner grabbing (seconds)"
    )

    parser.add_argument(
        "--cve-timeout",
        type=float,
        default=None,
        help="HTTP timeout for CVE lookups (seconds)"
    )

    parser.add_argument(
        "--cve-workers",
        type=int,
        default=None,
        help="Number of concurrent CVE lookup workers"
    )


    parser.add_argument(
        "-p",
        "--ports",
        help="Custom ports (example: 80,443 or 1-1024,8080)"
    )

    parser.add_argument(
        "--top-ports",
        type=int,
        help=f"Scan top N ports (1-{len(TOP_PORTS)})"
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Perform full vulnerability scan"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save output to JSON"
    )

    parser.add_argument(
        "--cvss",
        action="store_true",
        help="Show the computed CVSS 3.1 base score and severity band for each CVE"
    )

    parser.add_argument(
        "--http-headers",
        action="store_true",
        help="Analyze HTTP/HTTPS security headers on every HTTP(S) port found"
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable HTTPS certificate verification (use only for authorized testing)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show stage details and tracebacks for debugging",
    )

    args = parser.parse_args()

    #
    # Home screen
    #
    if args.command is None:

        show_banner()

        parser.print_help()

        return 0

    #
    # Config command
    #
    if args.command == "config":

        if args.config_action != "init":

            parser.error(
                "config requires a subcommand: init"
            )

        path = write_default_config()

        Logger.success(f"Default config written to {path}")

        return 0

    #
    # Scan command
    #
    if args.command == "scan":

        if not args.url:

            parser.error(
                "scan requires -u/--url"
            )

        print("\n「TUSK ACT 1」")

        host, url_port = parse_target(args.url)
        if not host:
            parser.error(f"Could not read a host from: {args.url}")

        target = Target(host)

        # Resolve which ports to scan: --full > --top-ports > -p/--ports > default.
        if args.full:
            target.ports = range(1, 65536)
        elif args.top_ports is not None:
            if not 1 <= args.top_ports <= len(TOP_PORTS):
                parser.error(f"--top-ports must be between 1 and {len(TOP_PORTS)}")
            target.ports = TOP_PORTS[:args.top_ports]
        elif args.ports:
            try:
                target.ports = parse_ports(args.ports)
            except ValueError as e:
                parser.error(f"Invalid value for -p/--ports: {e}")
        elif url_port:
            target.ports = [url_port]

        # Layered config: defaults -> TOML file -> env vars -> these CLI flags.
        config = ConfigManager(
            cli_overrides={
                "threads": args.threads,
                "port_timeout": args.port_timeout,
                "banner_timeout": args.banner_timeout,
                "cve_timeout": args.cve_timeout,
                "cve_workers": args.cve_workers,
            }
        )

        # Pass timeouts down into the scanner components for consistent tuning.
        scanner = Scanner(
            threads=config.get("threads"),
            port_timeout=config.get("port_timeout"),
            banner_timeout=config.get("banner_timeout"),
            cve_timeout=config.get("cve_timeout"),
            cve_workers=config.get("cve_workers"),
            nvd_api_key=config.get("nvd_api_key"),
            debug=args.verbose,
        )


        # Validate host (DNS) early to avoid ugly tracebacks later.
        resolved = resolve_host(target.host)
        if resolved is None:
            Logger.error(f"DNS lookup failed for: {target.host}")
            return 2

        try:
            with console.status(
                "[cyan]Rotating...[/cyan]",
                spinner="dots"
            ):

                scanner.run(
                    target
                )
        except KeyboardInterrupt:
            Logger.warning("Scan interrupted (Ctrl+C).")
            return 130
        except ValueError as e:
            Logger.error(str(e))
            return 2
        except Exception as e:
            Logger.error(f"Scan failed: {e}")
            return 3

        if any(e.stage == "port_discovery" for e in target.errors):
            return 3  # already logged by the scanner; don't print an empty report


        print()
        print("=" * 57)
        print("Tusk v0.1")
        print("=" * 57)

        print()
        print(f"[INF] Target: {target.host}")
        print()

        print(
            "PORT      STATE SERVICE VERSION"
        )

        print()

        for port in target.open_ports:

            service = target.services.get(
                port,
                "unknown"
            )

            info = target.versions.get(
                port,
                {
                    "product": "unknown",
                    "version": "unknown"
                }
            )

            product = info["product"]
            version = info["version"]

            print(
                f"{port}/tcp    open  "
                f"{service:<7} "
                f"{product} {version}"
            )

        print()
        print("-" * 57)

        print("\n[CPE]\n")

        for port, cpe in target.cpes.items():

            print(
                f"{port}/tcp -> {cpe}"
            )

        print()
        print("-" * 57)

        print("\n[VULN]\n")

        found = False

        for port, vulns in target.findings.items():

            if not vulns:

                continue

            found = True

            print(
                f"{port}/tcp\n"
            )

            for finding in vulns[:5]:

                print(
                    finding.cve_id
                )

                print(
                    f"Severity : {finding.severity}"
                )

                print(
                    f"CVSS : {finding.cvss_score}"
                )

                if args.cvss:

                    vector = finding.cvss_vector

                    if vector:
                        try:
                            result = calculate_cvss(vector)
                            print(
                                f"CVSS 3.1 (computed) : "
                                f"{result.base_score} ({result.severity}) "
                                f"[{vector}]"
                            )
                        except CVSSError as e:
                            print(f"CVSS 3.1 (computed) : unavailable ({e})")
                    else:
                        print("CVSS 3.1 (computed) : unavailable (no vector)")

                print()

        lookup_errors = [e for e in target.errors if e.stage == "cve_lookup"]
        if lookup_errors:
            for e in lookup_errors:
                print(f"CVE lookup failed: {e.message}")
        elif not found:
            print("No vulnerabilities found.")

        print(
            "-" * 57
        )

        http_headers_result = None

        if args.http_headers:

            print("\n[HTTP HEADERS]\n")

            try:
                analyzer = HttpAnalyzer(
                    timeout=config.get("cve_timeout"),
                    ruleset_path=config.get("ruleset_path"),
                    insecure=args.insecure,
                )

                http_headers_result = analyzer.analyze(
                    target.host,
                    target.open_ports,
                    target.banners,
                )
            except RuleEngineError as e:
                Logger.error(f"Ruleset error: {e}")
                return 2

            if not http_headers_result["evidence"]:

                print("No HTTP/HTTPS service responded.")

            else:

                for ev in http_headers_result["evidence"]:

                    print(f"{ev.port}/tcp  {ev.value}")

                if http_headers_result["matches"]:

                    print("\n[HTTP HEADER FINDINGS]\n")

                    for match in http_headers_result["matches"]:

                        print(
                            f"{match.rule_id} "
                            f"(confidence={match.confidence}, "
                            f"ruleset={match.ruleset_version}) "
                            f"-> {match.evidence.value}"
                        )

            print()
            print("-" * 57)

        if args.output:

            report = {
                "host": target.host,
                "open_ports": target.open_ports,
                "services": target.services,
                "banners": target.banners,
                "versions": target.versions,
                "cpes": target.cpes,
                "cves": target.cves,
                "findings": {
                    port: [f.to_dict() for f in flist]
                    for port, flist in target.findings.items()
                },
            }

            if http_headers_result is not None:
                report["http_headers"] = {
                    "evidence": [
                        ev.to_dict() for ev in http_headers_result["evidence"]
                    ],
                    "matches": [
                        {
                            "rule_id": m.rule_id,
                            "confidence": m.confidence,
                            "ruleset_version": m.ruleset_version,
                            "evidence": m.evidence.to_dict(),
                        }
                        for m in http_headers_result["matches"]
                    ],
                }

            try:
                with open(args.output, "w") as f:
                    json.dump(report, f, indent=2)
                Logger.success(f"Output written to {args.output}")
            except OSError as e:
                Logger.error(f"Failed to write output file: {e}")
                return 3

        if target.errors:
            return 3
        if any(target.findings.values()):
            return 1
        return 0


if __name__ == "__main__":

    sys.exit(main())

