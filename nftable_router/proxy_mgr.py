#!/usr/bin/env python3
"""
Proxy process supervision + proxy-chain (A via B) loop prevention.

New optional fields inside a nft_route.json proxy entry:

  "daemon":        "ss-redir" | "v2ray" | "sing-box" | "custom"  (absent = not managed)
  "uid":           LINE run-user (OPTIONAL; empty = processes run as the
                   current user and get no skuid identity rules). Binding a
                   line to a run-user is GLOBAL line logic -- it lives with
                   the line's basic info, not inside the managed proxy spec.
                   Two lines must NEVER share one uid (enforced in validate).
  "server":        upstream server address   (fallback: existing "proxy_ip")
  "server_port":   upstream server port
  "password": / "password_file":   ss-redir -k / -t
  "cipher":        ss-redir -m       (fallback: "method")
  "obfs":/ "obfs_param"/ "protocol":/ "protocol_param":  ss-redir extras
  "mode":          "tcp" | "tcp_and_udp"   (ss-redir -u)
  "config":        v2ray / sing-box json config path
  "cmd":           custom: argv template, {field} placeholders from the entry
  "args":          extra argv appended to any daemon command line
  "upstream":      line this proxy's own traffic chains through. If the
                   upstream line has its own run-user, our process executes
                   AS THAT USER (identity binding -> the upstream line's
                   skuid rules route its egress); port-type upstreams keep
                   the classic consumer-keyed redirect.
  "autostart":     default true; false = supervise only if started manually
  "restart":       {"max": N, "window": seconds} rate-limit (default 5/300)

skuid identity rules (one set per LINE that has a run-user; comment-tagged,
managed entirely here -- INSERT at HEAD of nat_OUTPUT for verdict rules so
they run BEFORE the policy NFQUEUE; mark stamps go into the iface_bind
TYPE-ROUTE output chain because a mark set after the routing decision never
steers egress):
  managed, upstream = port-line B : skuid A, tcp, daddr != @local,
                                   dport != port(B) -> redirect :port(B)
  managed, upstream = mark-line M : skuid A -> meta mark set M (+ct save)
                                   [skipped when M has its own run-user: the
                                    process then runs as M's user and M's own
                                    stamp rule covers it]
  managed, direct, line has mark  : skuid A -> meta mark set own mark (+ct)
  managed, direct, no mark        : skuid A, daddr != @local -> accept
  plain mark line w/ run-user     : skuid X -> meta mark set own mark (+ct)
Self-loop / cycle / missing-upstream / unmanaged-upstream / duplicate uid are
rejected at plan time; chain start order is topological (deepest dependency
first); each dependency's listen port is verified reachable before the
dependent process is spawned.
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
    """Resolve the LINE's run-user ('uid') -> int. Empty/unset -> None:
    no skuid identity, processes simply run as the current user. Raises
    ValueError only for a named user that does not exist on the system."""
    u = proxy_cfg.get("uid")
    if u is None or (isinstance(u, str) and not u.strip()):
        return None
    if isinstance(u, int):
        return u
    try:
        return int(u)
    except ValueError:
        pass
    try:
        return pwd.getpwnam(u).pw_uid
    except KeyError:
        raise ValueError("unknown uid/user %r for proxy %s" % (u, what))


def uid_identity(u):
    """comparable identity for duplicate-run-user checks: resolved int when
    the account exists, else the raw string."""
    try:
        return int(u)
    except (TypeError, ValueError):
        pass
    try:
        return pwd.getpwnam(str(u)).pw_uid
    except KeyError:
        return str(u)


def identity_line(proxy_cfgs, name, uid_cache=None):
    """run-user under which the managed PROCESS executes -- deliberately
    decoupled from the per-uid nft rules (plan_proxy_chain_rules emits those
    for every line that has its own run-user, keyed on skuid, independent of
    this choice):
      mark-type upstream WITH a run-user  -> inherit IT (hkvmiss/ss-redir runs
          as hkfib's user and hkfib's own stamp steers the egress; 'managed
          only by the upstream line's skuid')
      otherwise                           -> the line keeps its own identity
    uid_cache (resolved name->int|None) guards against adopting an upstream
    whose account fails to resolve (would silently run the process as its own
    user while no stamp rule matches it)."""
    cfg = proxy_cfgs.get(name) or {}
    up = upstream_of(cfg)
    if up and upstream_kind(proxy_cfgs, up) == "mark":
        u_up = (proxy_cfgs.get(up) or {}).get("uid")
        if u_up is not None and not (isinstance(u_up, str) and not u_up.strip()) and \
                (uid_cache is None or uid_cache.get(up) is not None):
            return up
    return name


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


MARKSO = os.path.join(os.path.dirname(os.path.realpath(__file__)), "markexec.so")
MARKSRC = os.path.join(os.path.dirname(os.path.realpath(__file__)), "markexec.c")


def ensure_markso():
    """compile markexec.so (LD_PRELOAD SO_MARK shim) on demand; -> (path|None, err)"""
    try:
        if os.path.exists(MARKSO) and os.path.getmtime(MARKSO) >= os.path.getmtime(MARKSRC):
            return MARKSO, None
    except OSError:
        pass
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        return None, "no cc/gcc available to build markexec.so"
    try:
        p = subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", MARKSO, MARKSRC],
                           capture_output=True, timeout=25, text=True)
        if p.returncode != 0:
            return None, "compile failed: " + (p.stderr or "")[-200:]
        return MARKSO, None
    except Exception as e:
        return None, str(e)


def probe_env(mark, base_env=None):
    """env for a marked child process (dig/curl/mtr); falls back to unmarked
    with error text so callers can log the degradation once."""
    env = dict(base_env if base_env is not None else os.environ)
    if not mark:
        return env, None
    so, err = ensure_markso()
    if so:
        env["LD_PRELOAD"] = so
        env["MARK"] = str(int(mark))
        return env, None
    return env, err


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


def duplicate_users(proxy_cfgs):
    """GLOBAL skuid uniqueness: one run-user identifies exactly ONE line.
    Returns (offending_names:set, messages:list[str]). Deliberately NOT part
    of validate_chain: a collision poisons ONLY the lines involved, so the
    router quarantines exactly those (webadmin blocks saving new collisions
    up-front); a leftover dup in a hand-edited config must never take all
    proxy management down with it."""
    by_identity = {}
    for name, cfg in proxy_cfgs.items():
        u = cfg.get("uid")
        if u is None or (isinstance(u, str) and not u.strip()):
            continue
        by_identity.setdefault(uid_identity(u), []).append((name, u))
    names, msgs = set(), []
    for ident in sorted(by_identity, key=str):
        holders = by_identity[ident]
        if len(holders) < 2:
            continue
        for n, _ in holders:
            names.add(n)
        msgs.append("lines %s bind the same run-user (%s) -- a skuid may identify exactly ONE line"
                    % (" and ".join(sorted(n for n, _ in holders)), holders[0][1]))
    return names, msgs


def validate_chain(proxy_cfgs):
    """Returns ordered list [deepest dependency first]. Raises ValueError
    describing the first problem found (unknown/unmanaged/self/cycle).
    NOTE: run-user uniqueness is checked by duplicate_users() separately so a
    collision can quarantine just the involved lines instead of disabling
    every managed proxy at once."""
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

# skuid->fwmark identity stamps target iface_bind's dedicated TYPE-ROUTE output
# chain: a mark set in a filter/nat OUTPUT chain never re-triggers the FIB
# lookup (the routing decision for locally-generated packets happens earlier),
# which was the exact 'marked but egressed via default route' production bug.
# Command forms verified crash-free on the target nftables v0.9.8 by
# tools/type_route_probe.py. test asserts ROUTE_OUT_CHAIN == iface_bind.CHAIN_ROUTE.
ROUTE_OUT_CHAIN = "mangle_EGRESS_ROUTE"


def _stamp_rule(family, uid, mark):
    """skuid -> fwmark identity stamp, type-route OUTPUT chain so the packet
    is ROUTED by the mark (a filter chain sets it after the route lookup).
    Applies to tcp AND udp: the stamped mark is always an ip-rule routing
    line's mark (no tproxy listener), so it can never re-trigger a udp tproxy
    capture. A direct proxy is instead accept-guarded and, when it needs line
    routing, should run AS a mark line's user rather than be stamped itself."""
    return {"family": family, "table": "policy_route", "chain": ROUTE_OUT_CHAIN,
            "comment": CHAIN_CMT, "expr": [
                {"match": {"left": {"meta": {"key": "skuid"}}, "op": "==", "right": uid}},
                {"match": {"left": {"payload": {"protocol": family, "field": "daddr"}},
                           "op": "!=", "right": "@local"}},
                {"counter": {"bytes": 0, "packets": 0}},
                {"mangle": {"key": {"meta": {"key": "mark"}}, "value": int(mark)}},
                {"mangle": {"key": {"ct": {"key": "mark"}}, "value": {"meta": {"key": "mark"}}}},
            ]}


def plan_proxy_chain_rules(proxy_cfgs, uid_cache, family="ip"):
    """LINE-identity skuid rules (binding a line to a run-user is global
    line logic; the managed process may additionally RUN AS its mark-type
    upstream's user -- see identity_line -- and then needs no own rule):
      managed + upstream port-line B : skuid A -> redirect :port(B)  [nat_OUTPUT head]
      managed + upstream mark-line M (M without own run-user): skuid A -> stamp M.mark
      managed direct, line has mark  : skuid A -> stamp own mark      [ROUTE chain]
      managed direct, no mark        : skuid A -> accept              [nat_OUTPUT head]
      plain mark line with run-user  : skuid X -> stamp own mark      [ROUTE chain]
    Verdict rules MUST be inserted at the head of nat_OUTPUT (before the
    policy NFQUEUE) or the queue verdicts first and these never run."""
    rules = []
    for name in proxy_cfgs:
        cfg = proxy_cfgs[name]
        uid = uid_cache.get(name)
        if uid is None:
            continue
        skuid = {"match": {"left": {"meta": {"key": "skuid"}}, "op": "==", "right": uid}}
        not_local = {"match": {"left": {"payload": {"protocol": family, "field": "daddr"}},
                               "op": "!=", "right": "@local"}}
        mark = cfg.get("mark") if isinstance(cfg.get("mark"), int) and cfg["mark"] > 0 else None
        if not is_managed(cfg):
            # pure identity line (an ip-rule upstream like hkfib, or any
            # mark line the admin gave a run-user): everything it runs egresses
            # through its own fwmark
            if mark is not None:
                rules.append(_stamp_rule(family, uid, mark))
            continue
        up_name = upstream_of(cfg)
        if up_name and upstream_kind(proxy_cfgs, up_name) == "port":
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
            continue
        up_mark = None
        if up_name:
            up_cfg = proxy_cfgs.get(up_name) or {}
            up_mark = up_cfg.get("mark")
        if up_mark is not None:
            # ip-rule upstream: stamp OUR egress with the UPSTREAM line's mark
            # (own skuid wins; a line that left uid empty never gets here --
            # identity_line runs it as the upstream's user and the upstream's
            # own stamp covers it). Never stamp our OWN line mark: for udp
            # tproxy lines re-marking our egress with the capture mark would
            # feed it back into our own listener.
            rules.append(_stamp_rule(family, uid, up_mark))
        else:
            # direct managed proxy: its upstream egress must never re-enter
            # the policy queue / its own tproxy capture (covers tcp AND udp)
            rules.append({"family": family, "table": "policy_route", "chain": "nat_OUTPUT",
                          "comment": CHAIN_CMT, "expr": [
                              skuid, not_local,
                              {"counter": {"bytes": 0, "packets": 0}},
                              {"accept": None}]})
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


PROXY_LOG_DIR = "/var/log/nft-route"
PROXY_LOG_MAX = 512 * 1024


def instance_logfile(key):
    """/var/log/nft-route/<line#tag>.log -- one per managed instance"""
    try:
        os.makedirs(PROXY_LOG_DIR, exist_ok=True)
    except OSError:
        pass
    return os.path.join(PROXY_LOG_DIR, key.replace("/", "_") + ".log")


def make_uid_spawner(uid, popen=None, logfile=None):
    """default spawn: drop privileges to the proxy's uid before exec, so the
    skuid-based chain/loop rules actually identify this traffic. Child
    stdout/stderr goes to the instance logfile (that's where -v verbosity
    and crash reasons land); spawn failures are recorded there too."""
    def spawn(argv):
        def _pre():
            if uid is not None:
                os.setgroups([])
                os.setgid(int(uid))
                os.setuid(int(uid))
        f = subprocess.DEVNULL
        fh = None
        if logfile:
            try:
                if os.path.exists(logfile) and os.path.getsize(logfile) > PROXY_LOG_MAX:
                    with open(logfile, "wb"):
                        pass  # cheap rotate: truncate before each fresh spawn
                fh = open(logfile, "ab")
                f = fh
            except OSError:
                f = subprocess.DEVNULL
        try:
            return (popen or subprocess.Popen)(argv, stdout=f, stderr=subprocess.STDOUT,
                                               stdin=subprocess.DEVNULL,
                                               preexec_fn=_pre if uid is not None else None)
        except OSError as e:
            if logfile:
                try:
                    with open(logfile, "ab") as _w:
                        _w.write(("%s spawn error: %s: %s | argv=%s\n"
                                  % (time.strftime("%H:%M:%S"), type(e).__name__, e,
                                     " ".join(str(a) for a in argv))).encode())
                except OSError:
                    pass
            raise
        finally:
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
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
            # EVERY line can own a run-user (global skuid identity), not only
            # managed ones: mark/upstream lines get stamp rules too.
            try:
                uid_cache[n] = get_uid(c, n)
            except ValueError as e:
                self.log("uid error: %s" % e)
                uid_cache[n] = None
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
            suid = uid_cache.get(identity_line(proxy_cfgs, n, uid_cache))
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
                spawn = self._spawn or make_uid_spawner(suid,
                                                        logfile=instance_logfile(key))
                p = ManagedProxy(key, icfg, argv, suid, line=n,
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
        the whole line runs under its IDENTITY user (own uid, or the uid of
        its mark-type upstream line), so one skuid rule covers all."""
        built, uids, lines = {}, {}, {}
        self.spec_errors = {}
        for n in order:
            c = proxy_cfgs[n]
            try:
                uids[n] = get_uid(c, n)
            except ValueError as e:
                self.log("uid error: %s" % e)
                uids[n] = None
            if not is_managed(c):
                continue
            suid = uids.get(identity_line(proxy_cfgs, n, uids))
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
                spawn = self._spawn or make_uid_spawner(suid, logfile=instance_logfile(key))
                built[key] = ManagedProxy(key, icfg, argv, suid, line=n,
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
