# -*- coding: utf-8 -*-
"""Embedded single-page UI for webadmin (no external assets / CDN).

Content lives in webui_parts/ (styles / HTML sections / per-tab JS) -- this
file only assembles them in the right order and stamps UI_VERSION. See
webadmin._load_ui(): it hot-reloads whenever ANY file listed in
SOURCE_FILES changes mtime, not just this file -- editing a file under
webui_parts/ takes effect exactly like editing this file used to.
"""

import os

# bump on every UI behaviour change: /api/config refuses saves from older
# cached pages (they may reconstruct payloads with missing keys)
UI_VERSION = "20260905-1230"

_here = os.path.dirname(os.path.realpath(__file__))
_parts_dir = os.path.join(_here, "webui_parts")

# JS concatenation order matters (one inline <script>, plain globals, no ES
# modules): common.js defines shared infra every tab depends on and must
# come first; boot.js kicks off the initially-visible tab's data load and
# must come last (needs every tab's load function already defined).
_JS_FILES = [
    "common.js",
    "tab_flow.js",
    "tab_bind.js",
    "tab_proxy.js",
    "tab_rules.js",
    "tab_cfg.js",
    "tab_rt.js",
    "tab_mtr.js",
    "tab_info.js",
    "tab_dns.js",
    "tab_sw.js",
    "tab_tools.js",
    "boot.js",
]
# HTML section order is cosmetic (only nav-button data-t -> #s-<t> id lookup
# matters, not DOM position; sections are display:none unless .sel).
_HTML_FILES = [
    "shell_head.html",
    "tab_flow.html",
    "tab_bind.html",
    "tab_proxy.html",
    "tab_rules.html",
    "tab_mtr.html",
    "tab_rt.html",
    "tab_tools.html",
    "tab_dns.html",
    "tab_sw.html",
    "tab_cfg.html",
    "tab_info.html",
    "shell_tail.html",
]

SOURCE_FILES = [os.path.realpath(__file__)] + [
    os.path.join(_parts_dir, name) for name in (["styles.css"] + _HTML_FILES + _JS_FILES)
]


def _read(name):
    with open(os.path.join(_parts_dir, name), "r", encoding="utf-8") as f:
        return f.read()


_CSS = _read("styles.css")
_HTML = "".join(_read(name) for name in _HTML_FILES)
_JS = "\n".join(_read(name) for name in _JS_FILES)

INDEX_HTML = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nft-route 管理台</title>
<script>var UI_VER="%s";</script>
<style>
%s
</style></head><body>
%s
<script>
%s
</script></body></html>""" % (UI_VERSION, _CSS, _HTML, _JS)
