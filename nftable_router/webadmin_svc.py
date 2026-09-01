#!/usr/bin/env python3
"""
Webadmin child-service lifecycle, used by router.py (the 'main app') to run
the web admin as a supervised CHILD PROCESS next to the router itself.

Design:
  * launch via subprocess.Popen (fresh interpreter, NO fork of router state:
    no inherited NFQUEUE socket / redis conns / signal mask)
  * crash restart with the same rate-limit semantics as proxy daemons
    (max N restarts per window -> giveup until next reload)
  * config section in nft_route.json:
      "webadmin": {"enabled": true, "host": "127.0.0.1", "port": 8788,
                   "redis_host": "127.0.0.1", "redis_port": 6379, "redis_db": 1,
                   "log": "/var/log/nft_webadmin.log",
                   "restart": {"max": 5, "window": 300}}
    absent section = enabled-by-default on 127.0.0.1:8788; "enabled": false
    turns the child off entirely.
  * reconcile(config) on boot and on every SIGUSR1 reload: only restarts the
    child when the (host,port,...) spec actually changed.
"""

import os
import subprocess
import sys
import time

DEFAULTS = {"host": "127.0.0.1", "port": 8788, "redis_host": "127.0.0.1",
            "redis_port": 6379, "redis_db": 1, "log": None,
            "max": 5, "window": 300}


def parse_spec(config):
    w = (config or {}).get("webadmin", {})
    if isinstance(w, bool):
        w = {"enabled": w}
    if not w.get("enabled", True):
        return None
    rl = w.get("restart", {})
    return {
        "host": str(w.get("host", DEFAULTS["host"])),
        "port": int(w.get("port", DEFAULTS["port"])),
        "redis_host": str(w.get("redis_host", DEFAULTS["redis_host"])),
        "redis_port": int(w.get("redis_port", DEFAULTS["redis_port"])),
        "redis_db": int(w.get("redis_db", DEFAULTS["redis_db"])),
        "log": w.get("log"),
        "max": int(rl.get("max", DEFAULTS["max"])),
        "window": float(rl.get("window", DEFAULTS["window"])),
    }


class WebadminService:
    def __init__(self, spawn=None, now=None, log=None, script=None):
        self._spawn = spawn or self._default_spawn
        self._now = now or time.time
        self.log = log or (lambda m: None)
        self.script = script                      # webadmin.py path (default: sibling file)
        self.spec = None
        self.proc = None
        self.state = "off"                        # off|running|backoff|gaveup
        self.hist = []

    # ------------------------------------------------------------------
    def _default_spawn(self, argv, outfile):
        out = open(outfile, "a+b") if outfile else subprocess.DEVNULL
        try:
            return subprocess.Popen(argv, stdout=out, stderr=out, stdin=subprocess.DEVNULL,
                                    start_new_session=True, close_fds=True)
        finally:
            if outfile and out:
                try:
                    out.close()
                except OSError:
                    pass

    def build_argv(self, spec, cfg_path, pidfile):
        script = self.script or os.path.join(os.path.dirname(os.path.realpath(__file__)), "webadmin.py")
        return [sys.executable, script,
                "--config", cfg_path,
                "--host", spec["host"], "--port", str(spec["port"]),
                "--redis-host", spec["redis_host"], "--redis-port", str(spec["redis_port"]),
                "--redis-db", str(spec["redis_db"]),
                "--pidfile", pidfile]

    # ------------------------------------------------------------------
    def reconcile(self, config, cfg_path, pidfile="/run/nft_route.pid"):
        """boot + USR1 entry: diff spec, restart child only when it changed."""
        spec = parse_spec(config)
        if spec == self.spec and self.proc is not None and self.proc.poll() is None:
            return "unchanged"
        self.stop_child()
        self.hist = []
        if spec is None:
            self.spec, self.state = None, "off"
            self.log("webadmin disabled by config")
            return "stopped"
        self.spec = spec
        self._start(cfg_path, pidfile)
        return "started"

    def _start(self, cfg_path, pidfile):
        argv = self.build_argv(self.spec, cfg_path, pidfile)
        try:
            self.proc = self._spawn(argv, self.spec.get("log"))
            self.state = "running"
            self.log("webadmin started pid=%s on http://%s:%d" % (self.proc.pid, self.spec["host"], self.spec["port"]))
        except OSError as e:
            self.proc = None
            self.state = "backoff"
            self.log("webadmin spawn failed: %s" % e)

    def tick(self, cfg_path, pidfile="/run/nft_route.pid"):
        """call periodically from the main loop: restart-if-died with rate limit."""
        if self.spec is None or self.proc is None or self.state == "gaveup":
            return
        rc = self.proc.poll()
        if rc is None:
            self.state = "running"
            return
        self.proc = None
        now = self._now()
        self.hist = [t for t in self.hist if now - t < self.spec["window"]]
        self.hist.append(now)
        if len(self.hist) > self.spec["max"]:
            self.state = "gaveup"
            self.log("webadmin died %d times in %.0fs (last rc=%s): giving up until next reload"
                     % (len(self.hist), self.spec["window"], rc))
            return
        self.log("webadmin exited rc=%s, restarting (%d/%d in window)"
                 % (rc, len(self.hist), self.spec["max"]))
        self.state = "backoff"
        self._start(cfg_path, pidfile)

    def stop_child(self):
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            except OSError:
                pass
        self.proc = None

    def shutdown(self):
        self.stop_child()
        self.state = "off"
