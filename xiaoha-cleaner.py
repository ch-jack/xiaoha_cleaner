#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stable public launcher for 秒杀小哈."""

from __future__ import print_function

import os
import sys

from XiaohaCleanerAuto import main as cli_main


def hide_console_window():
    """Hide the PyInstaller console only when the no-argument GUI is used."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return
    try:
        import ctypes
        console = ctypes.windll.kernel32.GetConsoleWindow()
        if console:
            ctypes.windll.user32.ShowWindow(console, 0)
    except Exception:
        pass


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--gui-smoke-test"]:
        from XiaohaCleanerGui import smoke_test
        return smoke_test()
    if arguments:
        return cli_main(arguments)

    hide_console_window()
    from XiaohaCleanerGui import main as gui_main
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
