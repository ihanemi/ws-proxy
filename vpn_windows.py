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

    # Windowed PyInstaller builds have no stderr. Preserve CLI diagnostics in
    # the same rotating log as the GUI instead of silently losing failures.
    if getattr(sys, "frozen", False):
        from vpn.logging_setup import configure_file_logging

        configure_file_logging(verbose="--verbose" in sys.argv)

    cli_main()


if __name__ == "__main__":
    main()
