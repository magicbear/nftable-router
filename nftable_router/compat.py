#!/usr/bin/env python3
"""
Thin shims replacing dependencies that stopped being maintained, so the
package installs and runs on current Pythons (the deployed venv is 3.13).

  netifaces (last release 2021-05, abandoned)
      -> psutil, which is already a dependency and actively maintained.
         Only netifaces.interfaces() was ever used here.

  python-prctl (last release 2020-11, needs libcap headers to build)
      -> setproctitle (actively maintained) for the process title, and a
         3-line ctypes call for the per-thread name. Both are the same
         syscalls python-prctl wrapped; dropping it removes a C build
         dependency from the install.

  pytput (last release 2020-05)
      -> TputFormatter below. pytput imports pkg_resources, which
         setuptools 81 removed and which a 3.13 venv does not ship at all,
         so it raises ModuleNotFoundError on import there. The replacement
         keeps the same "{name:spec,style,style}" syntax and the same
         behaviour of emitting nothing when the output is not a colour
         terminal.

Every function degrades to a no-op rather than raising: a cosmetic process
title must never be able to take down packet processing.
"""

import ctypes
import ctypes.util
import os
import string
import sys

PR_SET_NAME = 15

_libc = None


def _libc_handle():
    global _libc
    if _libc is None:
        try:
            _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        except OSError:
            _libc = False
    return _libc or None


def interfaces():
    """Names of the local network interfaces (netifaces.interfaces())."""
    try:
        import psutil
        return list(psutil.net_if_addrs().keys())
    except Exception:
        pass
    try:                       # Linux fallback, no dependency at all
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def set_thread_name(name):
    """Per-thread name shown in `ps -L` / /proc/<pid>/task/<tid>/comm.
    Kernel truncates at 15 chars + NUL (as it did under python-prctl)."""
    lib = _libc_handle()
    if lib is None:
        return False
    try:
        raw = name.encode("utf-8", "replace")[:15]
        return lib.prctl(PR_SET_NAME, ctypes.c_char_p(raw), 0, 0, 0) == 0
    except Exception:
        return False


def set_proctitle(title):
    """Process title shown in `ps` (rewrites argv[0])."""
    try:
        import setproctitle
        setproctitle.setproctitle(title)
        return True
    except ImportError:
        pass
    except Exception:
        return False
    # setproctitle absent: at least set the comm name so the process is
    # still identifiable, even though `ps` will show the old argv.
    return set_thread_name(title)


# ---------------------------------------------------------------------------
# pytput replacement
# ---------------------------------------------------------------------------

_SGR = {
    "bold": "1", "dim": "2", "underline": "4", "blink": "5", "reverse": "7",
    "black": "30", "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "purple": "35", "magenta": "35", "cyan": "36", "white": "37",
    "bg_black": "40", "bg_red": "41", "bg_green": "42", "bg_yellow": "43",
    "bg_blue": "44", "bg_purple": "45", "bg_magenta": "45", "bg_cyan": "46",
    "bg_white": "47",
}
_RESET = "\033[0m"


def _color_capable():
    """Same gate pytput applied: style only a real colour terminal, so
    redirecting the router's output to a log file does not fill it with
    escape sequences."""
    if os.environ.get("NO_COLOR"):
        return False
    term = os.environ.get("TERM", "")
    if not term or term == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


class TputFormatter(string.Formatter):
    """Drop-in for pytput.TputFormatter.

    Format spec is "<normal spec>,<style>,<style>...", e.g.
        "{msg:s,bg_red,black}"   "{dev:12s,cyan,bold}"   "{n:3d,green}"
    The leading part is handed to normal str.format, then the styles wrap
    the *already padded* result -- matching pytput, whose padding is inside
    the escape sequences.
    """

    def __init__(self, force_color=None):
        super().__init__()
        self._force = force_color

    def _enabled(self):
        return _color_capable() if self._force is None else self._force

    def format_field(self, value, format_spec):
        spec, _, styles = (format_spec or "").partition(",")
        text = format(value, spec)
        if not styles:
            return text
        if not self._enabled():
            return text
        codes = [_SGR[s] for s in
                 (p.strip() for p in styles.split(",")) if s in _SGR]
        if not codes:
            return text
        return "".join("\033[%sm" % c for c in codes) + text + _RESET
