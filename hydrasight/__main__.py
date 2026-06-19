"""Entry point — python -m hydrasight"""
import sys
import traceback

from hydrasight.config.loader import load_config
from hydrasight.cli.shell import Shell


def main() -> None:
    if sys.version_info < (3, 10):
        print("[!] Python 3.10+ required")
        sys.exit(1)
    cfg = load_config()
    try:
        Shell(cfg).run()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)
    except Exception:  # noqa: BLE001
        print("\n[!] fatal error:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
