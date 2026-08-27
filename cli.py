import argparse
import json

from rich.console import Console

from core.target import Target
from core.scanner import Scanner
from core.utils import resolve_host
from core.logger import Logger
from core.config.config_manager import ConfigManager, write_default_config
from scoring.cvss import calculate as calculate_cvss, CVSSError
from discovery.ports import TOP_PORTS
from discovery.analyzers.http_analyzer import HttpAnalyzer


console = Console()



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

  tusk scan -u example.com --top-ports 1000

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
        help="Target host"
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
        help="Custom ports (example: 80,443)"
    )

    parser.add_argument(
        "--top-ports",
        type=int,
        help="Scan top N ports"
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
        help="Analyze HTTP/HTTPS security headers on ports 80/443"
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

        return

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

        return

    #
    # Scan command
    #
    if args.command == "scan":

        if not args.url:

            parser.error(
                "scan requires -u/--url"
            )

        print("\n「TUSK ACT 1」")

        target = Target(
            args.url
        )

        # Resolve which ports to scan: --full > --top-ports > -p/--ports > default.
        if args.full:
            target.ports = range(1, 65536)
        elif args.top_ports is not None:
            target.ports = TOP_PORTS[:args.top_ports]
        elif args.ports:
            try:
                target.ports = [
                    int(p.strip())
                    for p in args.ports.split(",")
                    if p.strip()
                ]
            except ValueError:
                parser.error(
                    f"Invalid value for -p/--ports: {args.ports}"
                )

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
            debug=args.verbose,
        )


        # Validate host (DNS) early to avoid ugly tracebacks later.
        resolved = resolve_host(args.url)
        if resolved is None:
            Logger.error(f"DNS lookup failed for: {args.url}")
            return

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
            return
        except ValueError as e:
            Logger.error(str(e))
            return
        except Exception as e:
            Logger.error(f"Scan failed: {e}")
            return


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

        if not found:

            print(
                "No vulnerabilities found."
            )

        print(
            "-" * 57
        )

        http_headers_result = None

        if args.http_headers:

            print("\n[HTTP HEADERS]\n")

            analyzer = HttpAnalyzer(
                timeout=args.cve_timeout if args.cve_timeout else 10,
                ruleset_path=config.get("ruleset_path"),
                insecure=args.insecure,
            )

            http_headers_result = analyzer.analyze(
                target.host,
                target.open_ports,
            )

            if not http_headers_result["evidence"]:

                print("No HTTP/HTTPS service responded on port 80/443.")

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


if __name__ == "__main__":

    main()

