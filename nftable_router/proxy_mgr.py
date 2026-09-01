#!/usr/bin/env python3
"""
Proxy process supervision + proxy-chain (A via B) loop prevention.

New optional fields inside a nft_route.json proxy entry:

  "daemon":        "ss-redir" | "v2ray" | "sing-box" | "custom"  (absent = not managed)
  "uid":           run-user name (REQUIRED for chained proxies; skuid matching)
  "server":        upstream server address   (fallback: existing "proxy_ip")
  "server_port":   upstream server port
  "password": / "password_file":   ss-redir -k / -t
  "cipher":        ss-redir -m       (fallback: "method")
  "obfs":/ "obfs_param"/ "protocol":/ "protocol_param":  ss-redir extras
  "mode":          "tcp" | "tcp_and_udp"   (ss-redir -u)
  "config":        v2ray / sing-box json config path
  "cmd":           custom: argv template, {field} placeholders from the entry
  "args":          extra argv appended to any daemon command line
  "upstream":      proxy_id whose transparent port this proxy's own traffic
                   should be chained through (enables ProxyA-via-ProxyB)
  "autostart":     default true; false = supervise only if started manually
  "restart":       {"max": N, "window": seconds} rate-limit (default 5/300)

Loop prevention / chain rules (INSERTED at the HEAD of nat_OUTPUT so they
run BEFORE the policy NFQUEUE rule and the per-mark tproxy redirects;
comment-tagged, managed entirely here because we know each proxy's uid):
  chained (has "upstream"):
    meta skuid == uid(A), tcp, daddr != @local, tcp dport != port(B)
      -> redirect to port(B)          # incl. A's own server: that IS the chain
  direct (managed, uid set, no upstream):
    meta skuid == uid(A), daddr != @local -> accept
      # exempts A's upstream traffic from policy marking, which could
      # otherwise redirect it into A's own listener (self-loop)
Self-loop / cycle / missing-upstream / unmanaged-upstream are rejected at
plan time; chain start order is topological (deepest dependency first);
each dependency's listen port is verified reachable before the dependent
process is spawned.
"""

import errno
import json
import os
import pwd
import re
import select
import signal
import socket
import subprocess
import threading
import time

DAEMONS = ("ss-redir", "v2ray", "sing-box", "custom")
CHAIN_CMT = "**AUTOGEN BY PolicyRoute proxy-chain**"
SECRET_KEYS = ("password", "k", "-k")


# ---------------------------------------------------------------------------
# spec parsing / command building
# ---------------------------------------------------------------------------

def is_managed(proxy_cfg):
    return bool(proxy_cfg.get("daemon"))


def get_uid(proxy_cfg, what=""):
    """Resolve uid/user name -> int; raises ValueError."""
    u = proxy_cfg.get("uid")
    if u is None:
        raise ValueError("proxy %s must define 'uid' (skuid loop-guard)" % what)
    if isinstance(u, int):
        return u
    try:
        return pwd.getpwnam(u).pw_uid
    except KeyError:
        raise ValueError("unknown uid/user %r for proxy %s" % (u, what))


def build_cmd(name, cfg):
    """Return argv list for the daemon. Raises ValueError on bad config."""
    daemon = cfg.get("daemon")
    if daemon not in DAEMONS:
        raise ValueError("%s: unknown daemon %r" % (name, daemon))
    if not cfg.get("port"):
        raise ValueError("%s: missing local transparent 'port'" % name)
    extra = [str(a) for a in cfg.get("args", [])]

    if daemon == "ss-redir":
        argv = ["/usr/sbin/ss-redir", "-b", "0.0.0.0", "-l", str(cfg["port"])]
        server = cfg.get("server") or cfg.get("proxy_ip")
        if not server:
            raise ValueError("%s: ss-redir needs 'server'/'proxy_ip'" % name)
        argv += ["-s", str(server)]
        if cfg.get("server_port"):
            argv += ["-p", str(cfg["server_port"])]
        if cfg.get("cipher") or cfg.get("method"):
            argv += ["-m", str(cfg.get("cipher") or cfg.get("method"))]
        if cfg.get("password_file"):
            argv += ["-t", str(cfg["password_file"])]
        elif cfg.get("password") is not None:
            argv += ["-k", str(cfg["password"])]
        else:
            raise ValueError("%s: ss-redir needs 'password' or 'password_file'" % name)
        for opt, key in (("-g", "obfs"), ("-G", "obfs_param"),
                         ("-O", "protocol"), ("-o", "protocol_param")):
            if cfg.get(key):
                argv += [opt, str(cfg[key])]
        if str(cfg.get("mode", "tcp")).lower() in ("tcp_and_udp", "udp", "both"):
            argv.append("-u")
        return argv + extra

    if daemon in ("v2ray", "sing-box"):
        binary = cfg.get("binary", daemon)
        conf = cfg.get("config")
        if not conf:
            raise ValueError("%s: daemon %s needs 'config' path" % (name, daemon))
        if not os.path.exists(conf):
            raise ValueError("%s: config file missing: %s" % (name, conf))
        if daemon == "v2ray":
            return [binary, "-config", conf] + extra
        return [binary, "run", "-c", conf] + extra

    # custom: template argv with {field} substitution from the entry itself
    tmpl = cfg.get("cmd")
    if not tmpl or not isinstance(tmpl, list):
        raise ValueError("%s: custom daemon needs 'cmd' argv list" % name)
    def sub(tok):
        try:
            return re.sub(r"\{(\w+)\}", lambda m: str(cfg[m.group(1)]), tok)
        except KeyError:
            raise ValueError("%s: cmd placeholder {%%s} not in config" % name)
    return [sub(str(t)) for t in tmpl] + extra


def redact(argv):
    """mask secret values (password) for any log output."""
    out, masking = [], False
    for i, tok in enumerate(argv):
        if masking:
            out.append("****")
            masking = False
            continue
        out.append(tok)
        if str(tok) in ("-k", "--password", "{password}") or (
                "=" in str(tok) and str(tok).split("=", 1)[0] in ("-k", "--password")):
            masking = True
    return out


# ---------------------------------------------------------------------------
# chain graph: cycles + topological order
# ---------------------------------------------------------------------------

def upstream_of(cfg):
    up = cfg.get("upstream")
    return None if up in (None, "", False) else str(up)


def validate_chain(proxy_cfgs):
    """Returns ordered list [deepest dependency first]. Raises ValueError
    describing the first problem found (unknown/unmanaged/self/cycle)."""
    for name, cfg in proxy_cfgs.items():
        up = upstream_of(cfg)
        if up is None:
            continue
        if up == name:
            raise ValueError("%s: upstream points to itself" % name)
        if up not in proxy_cfgs:
            raise ValueError("%s: unknown upstream %r" % (name, up))
        if not is_managed(proxy_cfgs[up]):
            raise ValueError("%s: upstream %s is not managed (no 'daemon'), "
                             "cannot guarantee it is up" % (name, up))
        if not proxy_cfgs[up].get("port"):
            raise ValueError("%s: upstream %s has no transparent 'port'" % (name, up))
    # DFS with colors for cycle + topo
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in proxy_cfgs}
    order, stack_path = [], []

    def visit(node):
        color[node] = GRAY
        stack_path.append(node)
        up = upstream_of(proxy_cfgs[node])
        if up is not None:
            if color[up] == GRAY:
                cyc = stack_path[stack_path.index(up):] + [up]
                raise ValueError("proxy chain loop: %s" % " -> ".join(cyc))
            if color[up] == WHITE:
                visit(up)
        color[node] = BLACK
        stack_path.pop()
        order.append(node)   # post-order: dependencies first

    for n in proxy_cfgs:
        if color[n] == WHITE:
            visit(n)
    return order  # deepest-first


# ---------------------------------------------------------------------------
# loop-guard / chain nft rules (pure dicts; committed by router.py via nfu)
# ---------------------------------------------------------------------------

def plan_proxy_chain_rules(proxy_cfgs, uid_cache, family="ip"):
    """Per managed proxy with a known uid, keyed on ITS OWN skuid:
      - chained  -> redirect to the upstream's transparent port
      - direct   -> accept (skip the policy queue / tproxy-mark redirects)
    Both guard against the self-connect loop where the policy engine marks a
    proxy's own upstream flow with a tproxy mark and redirects it back into
    its own listener. MUST be installed at the head of nat_OUTPUT (insert,
    not append) or the policy queue rule verdicts first and these never run."""
    rules = []
    for name in proxy_cfgs:
        cfg = proxy_cfgs[name]
        if not is_managed(cfg):
            continue
        uid = uid_cache.get(name)
        if uid is None:
            continue
        up_name = upstream_of(cfg)
        skuid = {"match": {"left": {"meta": {"key": "skuid"}}, "op": "==", "right": uid}}
        not_local = {"match": {"left": {"payload": {"protocol": family, "field": "daddr"}},
                               "op": "!=", "right": "@local"}}
        if not up_name:
            # direct managed proxy: its upstream egress must never re-enter
            # the policy queue (covers tcp AND udp)
            rules.append({"family": family, "table": "policy_route", "chain": "nat_OUTPUT",
                          "comment": CHAIN_CMT, "expr": [
                              skuid, not_local,
                              {"counter": {"bytes": 0, "packets": 0}},
                              {"accept": None}]})
            continue
        up_port = int(proxy_cfgs[up_name]["port"])
        expr = [
            skuid,
            {"match": {"left": {"meta": {"key": "l4proto"}}, "op": "==", "right": "tcp"}},
            not_local,
        ]
        # belt & braces: never redirect a flow whose dport already IS the
        # upstream port (would re-enter the same listener forever)
        expr.append({"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}},
                               "op": "!=", "right": up_port}})
        expr += [
            {"counter": {"bytes": 0, "packets": 0}},
            {"redirect": {"port": up_port}},
        ]
        rules.append({"family": family, "table": "policy_route", "chain": "nat_OUTPUT",
                      "comment": CHAIN_CMT, "expr": expr})
    return rules


# ---------------------------------------------------------------------------
# supervisor
# ---------------------------------------------------------------------------

def wait_port(port, host="127.0.0.1", timeout=10.0):
    """block until dependency's transparent port accepts TCP; True on success."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection((host, int(port)), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def make_uid_spawner(uid, popen=None):
    """default spawn: drop privileges to the proxy's uid before exec, so the
    skuid-based chain/loop rules actually identify this traffic."""
    def spawn(argv):
        def _pre():
            if uid is not None:
                os.setgroups([])
                os.setgid(int(uid))
                os.setuid(int(uid))
        return (popen or subprocess.Popen)(argv, preexec_fn=_pre if uid is not None else None)
    return spawn


class ManagedProxy:
    def __init__(self, name, cfg, argv, uid, spawn=None, sleeper=None, timer=None):
        self.name, self.cfg, self.argv, self.uid = name, cfg, argv, uid
        self._spawn = spawn or (lambda a: subprocess.Popen(a))
        self._sleep = sleeper or time.sleep
        self._time = timer or time.time
        self.proc = None
        self.state = "stopped"          # starting|running|backoff|gaveup|stopped|deferred|external
        self.restart_history = []
        self.stopping = False

    def start_once(self):
        self.state = "starting"
        self.proc = self._spawn(self.argv)
        self.state = "running"
        return self.proc

    def note_death(self):
        """rate-limited restart bookkeeping: returns wait-seconds or None=give up."""
        rl = self.cfg.get("restart", {})
        max_r, window = int(rl.get("max", 5)), float(rl.get("window", 300))
        now = self._time()
        self.restart_history = [t for t in self.restart_history if now - t < window]
        if len(self.restart_history) >= max_r:
            self.state = "gaveup"
            return None
        self.restart_history.append(now)
        n = len(self.restart_history)
        self.state = "backoff"
        return min(30, 2 ** (n - 1))   # 1,2,4,8,16,30...

    def stop(self, grace=5.0):
        self.stopping = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                end = self._time() + grace
                while self.proc.poll() is None and self._time() < end:
                    self._sleep(0.1)
                if self.proc.poll() is None:
                    self.proc.kill()
                    self.proc.wait()
            except OSError:
                pass
        self.state = "stopped"


class ProxySupervisor(threading.Thread):
    """Supervises all managed proxies in topo order with dependency-port
    gating; auto-restarts unexpected exits with rate limit. spawn/now/sleep
    are injectable for offline tests. on_status(name, state, pid) callback for UI/syslog."""
    def __init__(self, proxy_cfgs, spawn=None, sleep=None, now=None, on_status=None, log=None,
                 port_wait=None):
        threading.Thread.__init__(self, daemon=True)
        self.name_cfg = proxy_cfgs
        self._spawn = spawn
        self._sleep = sleep or time.sleep
        self._now = now or time.time
        self.on_status = on_status or (lambda *a: None)
        self.log = log or (lambda m: None)
        self._port_wait = port_wait or wait_port
        uid_cache = {}
        for n, c in proxy_cfgs.items():
            if is_managed(c):
                try:
                    uid_cache[n] = get_uid(c, n)
                except ValueError as e:
                    self.log("uid error: %s" % e)
        self.uid_cache = uid_cache
        self._stop_evt = threading.Event()
        self._lock = threading.RLock()   # guards self.proxies/order vs monitor thread
        self.order = validate_chain(proxy_cfgs)          # raises on cycle/bad upstream
        self.proxies = {}
        for n in self.order:
            c = proxy_cfgs[n]
            if not is_managed(c):
                continue
            argv = build_cmd(n, c)                       # raises on bad spec
            spawn = self._spawn or make_uid_spawner(uid_cache.get(n))
            p = ManagedProxy(n, c, argv, uid_cache.get(n),
                             spawn=spawn, sleeper=self._sleep, timer=self._now)
            self.proxies[n] = p

    def get(self, name):
        return self.proxies.get(name)

    def status(self):
        return {n: {"state": p.state,
                    "pid": p.proc.pid if p.proc and p.proc.poll() is None else None}
                for n, p in self.proxies.items()}

    # -- launch with dependency gating -------------------------------------
    def _bring_up(self, n):
        """start one proxy (dependency + external-port gated); call under lock.
        Waits are SHORT (the lock blocks reconfigure/monitor): on any gate
        failure the proxy is left in state 'deferred' and the monitor loop
        retries it every pacing tick."""
        p = self.proxies.get(n)
        if p is None or p.stopping:
            return
        if not self.name_cfg[n].get("autostart", True):
            return
        up = upstream_of(self.name_cfg[n])
        if up is not None:
            up_p = self.proxies.get(up)
            if up_p is None or up_p.proc is None or up_p.proc.poll() is not None:
                p.state = "deferred"
                self.log("%s: dependency %s not up, deferring" % (n, up))
                return
            port = self.name_cfg[up].get("port")
            # timeout=1.0: short (this runs under self._lock, long waits stall
            # reconfigure/monitor) but distinct from the 0.5 own-port probe
            # below so injected test stubs can tell the two probes apart
            if port and not self._port_wait(port, timeout=1.0):
                p.state = "deferred"
                self.log("%s: dependency %s port %s not ready, deferring" % (n, up, port))
                return
        my_port = self.name_cfg[n].get("port")
        if my_port and self._port_wait(my_port, timeout=0.5):
            p.state = "external"
            self.log("%s: port %s already listening (external instance?), not spawning"
                     % (n, my_port))
            self.on_status(n, "external", None)
            return
        try:
            p.start_once()
            self.on_status(n, p.state, p.proc.pid)
        except OSError as e:
            self.log("%s: spawn failed: %s" % (n, e))

    def launch(self):
        with self._lock:
            for n in self.order:
                self._bring_up(n)

    # -- incremental reconfiguration / restart-all -------------------------
    def _build_proxies(self, proxy_cfgs, order):
        built, uids = {}, {}
        for n in order:
            c = proxy_cfgs[n]
            if not is_managed(c):
                continue
            uid = None
            try:
                uid = get_uid(c, n)
            except ValueError as e:
                self.log("uid error: %s" % e)
            uids[n] = uid
            try:
                argv = build_cmd(n, c)
            except ValueError as e:
                self.log("%s: bad spec: %s (keeping previous instance if any)" % (n, e))
                if n in self.proxies:
                    built[n] = self.proxies[n]   # config error -> do NOT disturb running proxy
                    continue
                raise
            spawn = self._spawn or make_uid_spawner(uid)
            built[n] = ManagedProxy(n, c, argv, uid, spawn=spawn,
                                    sleeper=self._sleep, timer=self._now)
        return built, uids

    def reconfigure(self, proxy_cfgs, restart_all=False):
        """USR1 diff path (or USR2 with restart_all=True).
        - removed / now-unmanaged proxies            -> stopped
        - new ones                                   -> started (gated)
        - existing w/ changed argv                   -> stopped + started
        - existing unchanged                         -> kept running (proc moved over),
                                                        unless restart_all
        Raises ValueError (caller keeps everything) if the new config has a
        chain cycle / invalid reference; bad-spec on an already-running
        instance keeps the old process untouched instead of failing."""
        order = validate_chain(proxy_cfgs)              # raises -> nothing touched
        with self._lock:
            if self._stop_evt.is_set():
                raise ValueError("supervisor was stopped; create a new one")
            old = self.proxies
            built, uids = self._build_proxies(proxy_cfgs, order)
            for n in list(old):                          # removed from config
                if n not in built:
                    old[n].stop()
                    self.log("%s: removed from config, process stopped" % n)
                    self.on_status(n, "removed", None)
            for n, np in built.items():
                o = old.get(n)
                if o is None:
                    continue                             # brand new: bring-up below
                same = (np.argv == o.argv)
                if same and not restart_all:
                    np.restart_history = list(o.restart_history)
                    if o.proc is not None and o.proc.poll() is None:
                        np.proc, np.state = o.proc, "running"   # adopt running process
                        continue
                o.stop()                                 # changed / restart-all / dead-but-old
                self.log("%s: %s" % (n, "restart requested" if same else "config changed, restarting"))
            self.proxies, self.uid_cache = built, uids
            self.name_cfg, self.order = proxy_cfgs, order
            for n in self.order:
                p = self.proxies.get(n)
                if p is not None and p.proc is None and p.state not in ("external",):
                    self._bring_up(n)

    def restart_all(self):
        """USR2: stop + start every managed proxy (fresh rate-limit state)."""
        self.reconfigure(self.name_cfg, restart_all=True)

    def _monitor_loop(self, stop_evt):
        while not stop_evt.is_set():
            retry_wait = None
            for n, p in list(self.proxies.items()):
                with self._lock:
                    if self.proxies.get(n) is not p:
                        continue                     # replaced by reconfigure
                    if p.stopping:
                        continue
                    if p.proc is None:
                        # deferred earlier (dependency down / not ready):
                        # re-run the full gated bring-up
                        if p.state == "deferred":
                            self._bring_up(n)
                        continue
                    rc = p.proc.poll()
                    if rc is None or p.stopping:
                        continue
                    wait = p.note_death()
                    if wait is None:
                        self.log("%s: gave up after restart limit (last rc=%s)" % (n, rc))
                        self.on_status(n, "gaveup", None)
                        continue
                    self.log("%s: exited rc=%s, restart in %ss" % (n, rc, wait))
                    self.on_status(n, "backoff", None)
                    retry_wait = (n, p, wait)
                    break                            # sleep outside the lock
                # end with lock
                if retry_wait:
                    break
            if not retry_wait:
                # pacing: without this the loop busy-spins at 100% CPU while
                # every proxy is healthy (and hammers the RLock)
                if stop_evt.wait(1.0):
                    return
            if retry_wait:
                n, p, wait = retry_wait
                if stop_evt.wait(wait):
                    return
                with self._lock:
                    if self.proxies.get(n) is p and not p.stopping and p.proc is not None \
                            and p.proc.poll() is None:
                        continue                     # already healthy again
                    up = upstream_of(self.name_cfg.get(n, {}))
                    if up is not None:
                        up_p = self.proxies.get(up)
                        if up_p is None or not up_p.proc or up_p.proc.poll() is not None:
                            continue                 # dependency down: retried next round
                    try:
                        if self.proxies.get(n) is p:
                            p.start_once()
                            self.on_status(n, p.state, p.proc.pid)
                    except OSError as e:
                        self.log("%s: spawn failed: %s" % (n, e))

    def run(self):
        stop = self._stop_evt
        self.launch()
        self._monitor_loop(stop)

    def stop_all(self):
        self._stop_evt.set()
        for n in reversed(self.order):
            p = self.proxies.get(n)
            if p:
                p.stop()
                self.on_status(n, "stopped", None)
