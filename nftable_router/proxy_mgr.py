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
import shutil
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

# Fields that describe ONE PROCESS's connection (which server, which cipher,
# which transport plugin, which local mode). When a line is split via
# "instances" these must NOT silently fall back to the line-level value:
# instances are different processes and routinely need different servers/
# ciphers/plugins (e.g. a TCP instance tunnelled through v2ray-plugin over
# websocket+tls, and a UDP instance connecting bare to the same or a
# different endpoint -- v2ray-plugin does not carry UDP). Falling back used
# to mean a field left unset on one instance silently inherited the OTHER
# instance's sibling value via the shared line dict, which is exactly how a
# TCP instance could end up misconfigured while UDP looked fine (or vice
# versa) with no error. "daemon" and "port" stay line-shared on purpose:
# every instance of a line uses the same daemon binary and (usually) the
# same transparent port -- that's the point of splitting one line into
# multiple listener processes on it.
INSTANCE_SCOPED_FIELDS = frozenset((
    "mode", "plugin", "plugin_opts", "bind_addr",
    "cipher", "method", "password", "password_file",
    "server", "proxy_ip", "server_port",
    "obfs", "obfs_param", "protocol", "protocol_param",
    "binary", "config", "cmd",
))


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
    if daemon is None:
        raise ValueError("%s: missing 'daemon' field" % name)
    if daemon not in DAEMONS:
        raise ValueError("%s: unknown daemon %r" % (name, daemon))
    if not cfg.get("port"):
        raise ValueError("%s: missing local transparent 'port'" % name)
    extra = [str(a) for a in cfg.get("args", [])]

    if daemon == "ss-redir":
        # Debian: /usr/bin/ss-redir ; some builds /usr/sbin/ -> resolve via PATH
        ssb = cfg.get("binary") or shutil.which("ss-redir") or "/usr/sbin/ss-redir"
        argv = [ssb, "-b", str(cfg.get("bind_addr") or "0.0.0.0"), "-l", str(cfg["port"])]
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
        if cfg.get("plugin"):
            argv += ["--plugin", str(cfg["plugin"])]
        if cfg.get("plugin_opts"):
            argv += ["--plugin-opts", str(cfg["plugin_opts"])]
        mode = str(cfg.get("mode", "tcp")).lower()
        if mode in ("tcp_and_udp", "both"):
            argv.append("-u")
        elif mode == "udp":
            argv.append("-U")
        return argv + extra

    if daemon in ("v2ray", "sing-box"):
        binary = cfg.get("binary") or shutil.which(daemon) or daemon
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


def upstream_kind(proxy_cfgs, up_name):
    """'port' = chained through upstream transparent listener (redirect);
       'mark' = upstream is an ip-rule line (fwmark routing, tcp+udp, no
              listener / need not be managed);
       None   = not chainable."""
    up = proxy_cfgs.get(up_name)
    if up is None:
        return None
    if up.get("port"):
        return "port"
    if isinstance(up.get("mark"), int) and up.get("mark") > 0:
        return "mark"
    return None


def instances_of(name, cfg):
    """[(tag, merged_cfg)...]; a line without 'instances' yields one tag=''
    entry built from the line itself (single process, unchanged behaviour).

    A line WITH 'instances' is a multi-PROCESS split: line-shared fields
    (port, uid, upstream, autostart, restart, args, capability flags, ...)
    still fall through, but INSTANCE_SCOPED_FIELDS (server/cipher/password/
    plugin/mode/...) do NOT -- each instance must set its own, or it simply
    won't have them (build_cmd raises a clear error naming the instance
    rather than silently reusing a sibling instance's value)."""
    inst = cfg.get("instances")
    if not inst:
        return [("", cfg)]
    out = []
    for i, item in enumerate(inst):
        if not isinstance(item, dict):
            raise ValueError("%s: instances[%d] must be object" % (name, i))
        tag = str(item.get("name") or i)
        merged = {k: v for k, v in cfg.items() if k not in INSTANCE_SCOPED_FIELDS}
        merged.pop("instances", None)
        merged.update({k: v for k, v in item.items() if k != "name"})
        out.append((tag, merged))
    return out


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
        kind = upstream_kind(proxy_cfgs, up)
        if kind is None:
            raise ValueError("%s: upstream %s is not chainable (needs a "
                             "transparent 'port' or an ip-rule 'mark')" % (name, up))
        if kind == "port" and not is_managed(proxy_cfgs[up]):
            raise ValueError("%s: upstream %s has 'port' but no 'daemon' -- "
                             "cannot guarantee the listener is up" % (name, up))
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
        if upstream_kind(proxy_cfgs, up_name) == "mark":
            # ip-rule upstream: stamp this proxy's own egress with the
            # upstream line mark -> `ip rule fwmark M table M` sends it out
            # that line (works for tcp AND udp, no listener involved).
            up_mark = int(proxy_cfgs[up_name]["mark"])
            rules.append({"family": family, "table": "policy_route", "chain": "nat_OUTPUT",
                          "comment": CHAIN_CMT, "expr": [
                              skuid, not_local,
                              {"counter": {"bytes": 0, "packets": 0}},
                              {"mangle": {"key": {"meta": {"key": "mark"}}, "value": up_mark}},
                              {"mangle": {"key": {"ct": {"key": "mark"}},
                                           "value": {"meta": {"key": "mark"}}}},
                          ]})
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


PROXY_BINARIES = ("ss-redir", "ss-local", "ss-server", "v2ray", "sing-box")


def orphan_proxy_pids(port, binary_hint, master_pid):
    """processes whose argv[0] looks like a proxy daemon, that listen on
    -l <port>, and are NOT children of master_pid (orphans from a previous
    router run, supervisord copies, manual launches)."""
    out = []
    me = os.getpid()
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        pid = int(d)
        if pid == me:
            continue
        try:
            raw = open("/proc/%d/cmdline" % pid, "rb").read()
            cl = [c.decode("utf-8", "replace") for c in raw.split(b"\0") if c]
            ppid = int(re.search(r"^PPid:\s*(\d+)",
                                 open("/proc/%d/status" % pid).read(), re.M).group(1))
        except (OSError, ValueError, AttributeError):
            continue
        if not cl or ppid == master_pid:
            continue
        base = os.path.basename(cl[0])
        names = set(PROXY_BINARIES) | ({os.path.basename(str(binary_hint))} if binary_hint else set())
        if base not in names:
            continue
        try:
            i = cl.index("-l") + 1
            if i >= len(cl) or cl[i] != str(port):
                continue
        except ValueError:
            continue
        out.append({"pid": pid, "ppid": ppid, "cmd": " ".join(cl)[:120]})
    return out


def kill_orphan(pid, grace=1.5):
    """SIGTERM -> SIGKILL for a NON-child process (init reaps it)."""
    import time as _t
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    end = _t.time() + grace
    while _t.time() < end:
        try:
            st = open("/proc/%d/status" % pid).read()
        except OSError:
            return True
        if re.search(r"^State:\s*Z", st, re.M):
            return True
        _t.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return True


class ManagedProxy:
    def __init__(self, name, cfg, argv, uid, spawn=None, sleeper=None, timer=None, line=None):
        self.name, self.cfg, self.argv, self.uid = name, cfg, argv, uid
        self.line = line or name   # owning proxy-line name (instances share uid/chain rules)
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
        self.spec_errors = {}           # key -> build error (quarantined specs)
        self._stop_evt = threading.Event()
        self._lock = threading.RLock()   # guards self.proxies/order vs monitor thread
        self.order = validate_chain(proxy_cfgs)          # raises on cycle/bad upstream
        self.proxies = {}
        self.lines = {}                                  # line name -> [instance keys]
        for n in self.order:
            c = proxy_cfgs[n]
            if not is_managed(c):
                continue
            keys = []
            for tag, icfg in instances_of(n, c):
                key = n if not tag else "%s#%s" % (n, tag)
                try:
                    argv = build_cmd(key, icfg)
                except ValueError as e:
                    # per-instance quarantine: a broken spec must NEVER stop
                    # the other lines/instances from being supervised
                    self.log("%s: spec error, SKIPPED: %s" % (key, e))
                    self.spec_errors[key] = str(e)
                    continue
                spawn = self._spawn or make_uid_spawner(uid_cache.get(n))
                p = ManagedProxy(key, icfg, argv, uid_cache.get(n), line=n,
                                 spawn=spawn, sleeper=self._sleep, timer=self._now)
                self.proxies[key] = p
                keys.append(key)
            self.lines[n] = keys

    def get(self, name):
        return self.proxies.get(name)

    def status(self):
        return {n: {"state": p.state,
                    "pid": p.proc.pid if p.proc and p.proc.poll() is None else None}
                for n, p in self.proxies.items()}

    # -- launch with dependency gating -------------------------------------
    def _bring_up(self, key):
        """start one instance (dependency + external-port gated); call under
        lock. Waits are SHORT (the lock blocks reconfigure/monitor); on gate
        failure the instance stays state 'deferred' and the monitor retries."""
        p = self.proxies.get(key)
        if p is None or p.stopping:
            return
        cfg = p.cfg
        if not cfg.get("autostart", True):
            return
        up = upstream_of(cfg)
        if up is not None and self.lines.get(up):        # mark-type upstream: no processes to wait for
            for k2 in self.lines[up]:
                q = self.proxies.get(k2)
                if q is None or q.proc is None or q.proc.poll() is not None:
                    p.state = "deferred"
                    self.log("%s: dependency %s not up, deferring" % (key, up))
                    return
            for k2 in self.lines[up]:
                q = self.proxies.get(k2)
                uport = (q.cfg if q else {}).get("port")
                if uport and not self._port_wait(uport, timeout=1.0):
                    p.state = "deferred"
                    self.log("%s: dependency %s port %s not ready, deferring" % (key, up, uport))
                    return
        my_port = cfg.get("port")
        # external-instance probe: TCP connect sees only TCP listeners, so run
        # it only when NO sibling instance of this line is alive yet (a running
        # TCP plugin instance must not make the UDP-only instance look external)
        siblings = [k2 for k2 in self.lines.get(p.line, []) if k2 != key]
        sib_alive = any(self.proxies.get(k2) and self.proxies[k2].proc
                        and self.proxies[k2].proc.poll() is None for k2 in siblings)
        if my_port and not sib_alive and self._port_wait(my_port, timeout=0.5):
            # port busy by a foreign listener -> try TAKEOVER of stale proxies
            # (orphans of previous router runs / supervisor copies of the SAME
            # managed line). Only when the line allows it (takeover!=false).
            if cfg.get("takeover", False):
                for o in orphan_proxy_pids(my_port, cfg.get("binary"), os.getpid()):
                    self.log("%s: takeover killing stale proxy pid=%d ppid=%d [%s]"
                             % (key, o["pid"], o["ppid"], o["cmd"]))
                    kill_orphan(o["pid"])
                if not self._port_wait(my_port, timeout=0.8):
                    self.on_status(key, "takeover", None)
                    try:
                        p.start_once()
                        self.on_status(key, p.state, p.proc.pid)
                        return
                    except OSError as e:
                        p.state = "deferred"
                        self.log("%s: spawn failed after takeover: %s" % (key, e))
                        return
            p.state = "external"
            self.log("%s: port %s held by a live non-orphan listener (managed by "
                     "supervisor/another tool?) - not spawning; stop it there or set "
                     "'takeover': false" % (key, my_port))
            self.on_status(key, "external", None)
            return
        try:
            p.start_once()
            self.on_status(key, p.state, p.proc.pid)
        except OSError as e:
            p.state = "deferred"
            self.log("%s: spawn failed: %s" % (key, e))

    def launch(self):
        with self._lock:
            for n in self.order:
                for key in self.lines.get(n, []):
                    self._bring_up(key)

    # -- incremental reconfiguration / restart-all -------------------------
    def _build_proxies(self, proxy_cfgs, order):
        """-> (built_instances_by_key, uid_cache, lines_map). A line with
        'instances' yields one ManagedProxy per instance (key 'line#tag');
        they share the line uid, so one skuid anti-loop/chain rule covers all."""
        built, uids, lines = {}, {}, {}
        self.spec_errors = {}
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
            keys = []
            try:
                insts = instances_of(n, c)
            except ValueError as e:
                self.log("%s: bad instances: %s" % (n, e))
                insts = [("", c)]
            for tag, icfg in insts:
                key = n if not tag else "%s#%s" % (n, tag)
                try:
                    argv = build_cmd(key, icfg)
                except ValueError as e:
                    self.log("%s: spec error, SKIPPED: %s" % (key, e))
                    self.spec_errors[key] = str(e)
                    if key in self.proxies:
                        built[key] = self.proxies[key]   # keep running old instance
                        keys.append(key)
                    continue
                spawn = self._spawn or make_uid_spawner(uid)
                built[key] = ManagedProxy(key, icfg, argv, uid, line=n,
                                          spawn=spawn, sleeper=self._sleep, timer=self._now)
                keys.append(key)
            lines[n] = keys
        return built, uids, lines


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
            built, uids, lines = self._build_proxies(proxy_cfgs, order)
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
            self.lines = lines
            self.name_cfg, self.order = proxy_cfgs, order
            for n in self.order:
                for key in self.lines.get(n, []):
                    p = self.proxies.get(key)
                    if p is not None and p.proc is None and p.state not in ("external",):
                        self._bring_up(key)

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
                    up = upstream_of(p.cfg)
                    if up is not None and self.lines.get(up):
                        if any(not (self.proxies.get(k2) and self.proxies[k2].proc
                                    and self.proxies[k2].proc.poll() is None)
                               for k2 in self.lines[up]):
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
