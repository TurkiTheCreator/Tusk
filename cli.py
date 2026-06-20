import argparse

from rich.console import Console

from core.target import Target
from core.scanner import Scanner

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
│  Stand Abilities                                   │
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
        choices=["scan"],
        help="Command to execute"
    )

    parser.add_argument(
        "-u",
        "--url",
        help="Target host"
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Number of threads"
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

    args = parser.parse_args()

    #
    # Home screen
    #
    if args.command is None:

        show_banner()

        parser.print_help()

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

        scanner = Scanner(
            threads=args.threads
        )

        with console.status(
            "[cyan]Rotating...[/cyan]",
            spinner="dots"
        ):

            scanner.run(
                target
            )

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

            for vuln in vulns[:5]:

                print(
                    vuln["id"]
                )

                print(
                    f"Severity : {vuln['severity']}"
                )

                print(
                    f"CVSS : {vuln['cvss']}"
                )

                print()

        if not found:

            print(
                "No vulnerabilities found."
            )

        print(
            "-" * 57
        )


if __name__ == "__main__":

    main()

