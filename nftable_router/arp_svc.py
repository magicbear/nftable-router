#!/usr/bin/env python3
"""
Supervisor for the per-switch SNMP collectors (arp_snmp.py), replacing the
hand-written supervisord [program:arp-sw-*] blocks.

One CHILD PROCESS per switch, spawned via subprocess (never a fork of
router state: no inherited NFQUEUE socket / redis conns / signal mask), so
a hung or crashing SNMP walk can never stall packet processing -- that is
the whole point of keeping this out of the router's own process.

Config section in nft_route.json:

  "switches": {
    "enabled": true,
    "python": "python3.9",            # interpreter that HAS pysnmp; defaults
                                      # to the router's own sys.executable.
                                      # (Real constraint on the deployed
                                      # router: pysnmp is installed only for
                                      # python3.9 while the router itself
                                      # runs under python3.11.)
    "log_dir": "/var/log/nft_route",  # per-switch <name>.log, omit = no logs
    "poll_interval": 300,
    "iface_interval": 1800,
    "redis_host": "127.0.0.1", "redis_port": 6379, "redis_db": 1,
    "restart": {"max": 5, "window": 300},
    "devices": [
      {"name": "sw-ce6881", "ip": "192.168.11.1", "enabled": true,
       "community": "...",                                  # v2c
       "user": "monitor", "auth_key": "...", "priv_key": "..."}   # v3
    ]
  }

Restart semantics match proxy_mgr/webadmin_svc: N restarts per window then
"gaveup" until the next reload, so a permanently unreachable switch cannot
spin forever.
"""

import os
import subprocess
import sys
import time

DEFAULTS = {
    "poll_interval": 300,
    "iface_interval": 1800,
    "redis_host": "127.0.0.1",
    "redis_port": 6379,
    "redis_db": 1,
    "max": 5,
    "window": 300,
}


def parse_spec(config):
    """nft_route.json -> normalized spec, or None when the whole section is
    disabled/absent. Devices without an ip, or explicitly disabled, are
    dropped here so nothing downstream has to re-check."""
    w = (config or {}).get("switches", {})
    if isinstance(w, bool):
        w = {"enabled": w}
    if not w or not w.get("enabled", True):
        return None
    rl = w.get("restart", {}) or {}
    devices = []
    seen = set()
    for d in (w.get("devices") or []):
        if not isinstance(d, dict) or not d.get("ip"):
            continue
        if not d.get("enabled", True):
            continue
        name = str(d.get("name") or d["ip"])
        if name in seen:                       # duplicate names would collide
            continue                           # on redis SW::STATUS + log file
        seen.add(name)
        devices.append({
            "name": name,
            "ip": str(d["ip"]),
            "community": d.get("community") or None,
            "user": d.get("user") or None,
            "auth_key": d.get("auth_key") or d.get("authKey") or None,
            "priv_key": d.get("priv_key") or d.get("privKey") or None,
            "snmp_port": int(d.get("snmp_port", 161)),
        })
    if not devices:
        return None
    return {
        "python": str(w.get("python") or sys.executable),
        "log_dir": w.get("log_dir"),
        "poll_interval": int(w.get("poll_interval", DEFAULTS["poll_interval"])),
        "iface_interval": int(w.get("iface_interval", DEFAULTS["iface_interval"])),
        "redis_host": str(w.get("redis_host", DEFAULTS["redis_host"])),
        "redis_port": int(w.get("redis_port", DEFAULTS["redis_port"])),
        "redis_db": int(w.get("redis_db", DEFAULTS["redis_db"])),
        "max": int(rl.get("max", DEFAULTS["max"])),
        "window": float(rl.get("window", DEFAULTS["window"])),
        "devices": devices,
    }


def device_argv(spec, dev, script=None):
    script = script or os.path.join(os.path.dirname(os.path.realpath(__file__)), "arp_snmp.py")
    argv = [spec["python"], script,
            "--ip", dev["ip"], "--name", dev["name"],
            "--snmp-port", str(dev["snmp_port"]),
            "--poll-interval", str(spec["poll_interval"]),
            "--iface-interval", str(spec["iface_interval"]),
            "--redis-host", spec["redis_host"],
            "--redis-port", str(spec["redis_port"]),
            "--redis-db", str(spec["redis_db"])]
    if dev.get("community"):
        argv += ["--community", dev["community"]]
    if dev.get("user"):
        argv += ["--user", dev["user"]]
    if dev.get("auth_key"):
        argv += ["--authKey", dev["auth_key"]]
    if dev.get("priv_key"):
        argv += ["--privKey", dev["priv_key"]]
    return argv


def redact_argv(argv):
    """SNMP creds appear in /proc/<pid>/cmdline; mask them for any log/UI."""
    out, mask_next = [], False
    for tok in argv:
        if mask_next:
            out.append("****")
            mask_next = False
            continue
        out.append(tok)
        if tok in ("--community", "--authKey", "--privKey"):
            mask_next = True
    return out


class _Child:
    def __init__(self, dev, argv):
        self.dev = dev
        self.argv = argv
        self.proc = None
        self.state = "stopped"     # stopped|running|backoff|gaveup
        self.hist = []
        self.started_at = None
        self.last_rc = None


class ArpCollectorService:
    """Supervises one collector child per configured switch. spawn/now are
    injectable for offline tests (no real switches, no real processes)."""

    def __init__(self, spawn=None, now=None, log=None, script=None):
        self._spawn = spawn or self._default_spawn
        self._now = now or time.time
        self.log = log or (lambda m: None)
        self.script = script
        self.spec = None
        self.children = {}          # name -> _Child

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

    def _logfile(self, spec, name):
        if not spec.get("log_dir"):
            return None
        try:
            os.makedirs(spec["log_dir"], exist_ok=True)
        except OSError as e:
            self.log("log dir %s unusable (%s), logging disabled for %s" % (
                spec["log_dir"], e, name))
            return None
        return os.path.join(spec["log_dir"], "arp-%s.log" % name)

    def _start(self, spec, child):
        try:
            child.proc = self._spawn(child.argv, self._logfile(spec, child.dev["name"]))
            child.state = "running"
            child.started_at = self._now()
            self.log("collector %s (%s) started pid=%s" % (
                child.dev["name"], child.dev["ip"], child.proc.pid))
        except OSError as e:
            child.proc = None
            child.state = "backoff"
            self.log("collector %s spawn failed: %s" % (child.dev["name"], e))

    def _stop_child(self, child, grace=5):
        if child.proc is not None and child.proc.poll() is None:
            try:
                child.proc.terminate()
                try:
                    child.proc.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    child.proc.kill()
            except OSError:
                pass
        child.proc = None
        child.state = "stopped"

    # ------------------------------------------------------------------
    def reconcile(self, config, script=None):
        """Boot + SIGUSR1 entry. Only devices whose argv actually changed are
        restarted; untouched switches keep polling across reloads."""
        spec = parse_spec(config)
        if spec is None:
            if self.children:
                self.stop_all()
            self.spec = None
            return "stopped" if self.children == {} else "stopped"
        script = script or self.script
        want = {}
        for dev in spec["devices"]:
            want[dev["name"]] = device_argv(spec, dev, script)

        # removed / renamed
        for name in list(self.children):
            if name not in want:
                self._stop_child(self.children[name])
                self.log("collector %s removed from config, stopped" % name)
                del self.children[name]

        started = changed = kept = 0
        for dev in spec["devices"]:
            name = dev["name"]
            argv = want[name]
            cur = self.children.get(name)
            if cur is not None and cur.argv == argv and cur.proc is not None \
                    and cur.proc.poll() is None:
                cur.dev = dev
                kept += 1
                continue
            if cur is not None:
                if cur.argv != argv:
                    changed += 1
                self._stop_child(cur)
            child = _Child(dev, argv)
            self.children[name] = child
            self._start(spec, child)
            started += 1
        self.spec = spec
        self.log("collectors: %d started, %d unchanged, %d respec'd" % (started, kept, changed))
        return "started" if started else "unchanged"

    def tick(self):
        """Periodic: restart any child that died, with per-device rate limit."""
        if self.spec is None:
            return
        for name, child in self.children.items():
            if child.proc is None:
                if child.state in ("gaveup", "stopped"):
                    continue
                self._start(self.spec, child)
                continue
            rc = child.proc.poll()
            if rc is None:
                child.state = "running"
                continue
            child.last_rc = rc
            child.proc = None
            now = self._now()
            child.hist = [t for t in child.hist if now - t < self.spec["window"]]
            child.hist.append(now)
            if len(child.hist) > self.spec["max"]:
                child.state = "gaveup"
                self.log("collector %s died %d times in %.0fs (last rc=%s): giving up until reload"
                         % (name, len(child.hist), self.spec["window"], rc))
                continue
            self.log("collector %s exited rc=%s, restarting (%d/%d in window)"
                     % (name, rc, len(child.hist), self.spec["max"]))
            child.state = "backoff"
            self._start(self.spec, child)

    def status(self):
        out = []
        for name, c in sorted(self.children.items()):
            alive = c.proc is not None and c.proc.poll() is None
            out.append({
                "name": name,
                "ip": c.dev["ip"],
                "state": c.state if alive else ("gaveup" if c.state == "gaveup" else "not running"),
                "pid": c.proc.pid if alive else None,
                "uptime": (self._now() - c.started_at) if (alive and c.started_at) else None,
                "restarts": len(c.hist),
                "last_rc": c.last_rc,
                "cmd": " ".join(redact_argv(c.argv)),
            })
        return out

    def stop_all(self, grace=5):
        for name, child in self.children.items():
            self._stop_child(child, grace=grace)
            self.log("collector %s stopped" % name)
        self.children = {}
