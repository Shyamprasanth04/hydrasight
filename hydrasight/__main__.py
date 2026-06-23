"""Entry point — python -m hydrasight"""

import sys
import traceback

from hydrasight.cli.shell import Shell
from hydrasight.config.loader import load_config


def main() -> None:

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
