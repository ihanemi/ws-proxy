from __future__ import annotations

import sys


def main() -> None:
    if len(sys.argv) == 1 or "--gui" in sys.argv:
        if "--gui" in sys.argv:
            sys.argv.remove("--gui")
        from vpn.gui import main as gui_main

        gui_main()
        return

    from vpn.client import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
