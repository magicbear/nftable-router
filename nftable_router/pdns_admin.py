#!/usr/bin/env python3
"""
Backend for managing pdns-recursor.json (the PowerDNS Recursor Lua script's
config: forwarders / source_group / result_group / rules) + the poison-IP
list (dns_posion_list.txt) from the webadmin UI.

Pure functions, no server/socket state -- mirrors iface_bind.py's shape so
webadmin.py can wire it in the same way it wires ib.load_config/save_config.

PowerDNS Recursor commonly does NOT run on the same box as this router, so
every I/O function below takes an optional `host` ("user@1.2.3.4" /
"user@1.2.3.4:2222" / "user@[::1]:2222"): None (default) means local
filesystem access exactly as before; set means every read/write/stat and
the reload trigger go over `ssh`/`scp`, using whatever key/agent/~/.ssh/config
the invoking user already has set up -- this module never manages
credentials itself, and does NOT relax host-key checking (BatchMode=yes
means a broken/unaccepted-host-key setup fails fast with a clear error
instead of hanging on a password prompt that can never be answered here).

Schema (as read by pdns-recursor.lua's loadConfig()):
  forwarders:    {id: "host:port" | "host1,host2:port"}
  source_group:  {id: ["cidr", ...]}
  result_group:  {id: [{"type": "A"|"AAAA"|..., "value": "...", "ttl": N}, ...]}
  rules:         {domain_key: [{"action": "forwarder", "forwarder_id": id,
                                 "src_group_id": id?}
                                | {"action": "result", "rc_id": id,
                                   "src_group_id": id?}, ...]}
  domain_key is "default" or a dot-prefixed suffix like ".youtube.com."
  (pdns-recursor.lua walks queryname suffixes as ".label.label." -- a key
  WITHOUT the leading dot only ever matches an exact bare-apex query, never
  any subdomain, which in practice means it silently never matches real
  traffic. normalize_rules() below fixes this on every save so the UI can't
  reintroduce that bug.)
"""

import ipaddress
import json
import os
import shlex
import subprocess
import tempfile

RESERVED_ACTIONS = {"forwarder", "result"}
# short: this gates every page load when pdns_host is set (GET routes stat+
# read remotely) -- a human waiting on a web UI shouldn't eat an 8s+ hang
# just because the box is briefly unreachable. Legitimate cross-DC/VPN
# links complete their SSH handshake in well under a second regardless.
SSH_CONNECT_TIMEOUT = 5


# ---------------------------------------------------------------------------
# ssh transport (used by every function below when `host` is set)
# ---------------------------------------------------------------------------

def _ssh_prefix(host, connect_timeout=SSH_CONNECT_TIMEOUT):
    """host -> ssh argv prefix, ending right before the remote command.
    BatchMode=yes: fail fast on missing/unagented keys instead of hanging on
    a password prompt nothing here can answer. Host key checking is left at
    its default (strict) -- this module does not weaken it."""
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % connect_timeout]
    h = host
    # optional :port -- only stripped when unambiguous, so bare (unbracketed)
    # IPv6 targets (which contain many colons of their own) pass through
    # untouched; bracketed IPv6 ("user@[::1]:2222") is handled correctly.
    tail = h.rsplit("]", 1)[-1] if "]" in h else h
    if tail.count(":") == 1:
        maybe_host, _, maybe_port = h.rpartition(":")
        if maybe_port.isdigit():
            h, port = maybe_host, maybe_port
            argv += ["-p", port]
    argv.append(h)
    return argv


class RemoteError(OSError):
    pass


def _ssh_exec(host, remote_cmd, input_bytes=None, timeout=15):
    """Run `remote_cmd` (a single shell string, already quoted by the
    caller) on `host`. Returns (returncode, stdout_bytes, stderr_bytes).
    Raises RemoteError on ssh-level failure (host unreachable, auth failed,
    timeout) -- NOT on the remote command's own nonzero exit, which callers
    inspect themselves (e.g. "file not found" vs "ssh never connected" need
    different handling)."""
    try:
        p = subprocess.run(_ssh_prefix(host) + [remote_cmd], input=input_bytes,
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RemoteError("ssh %s 超时 (%ss): %s" % (host, timeout, remote_cmd[:60]))
    except OSError as e:
        raise RemoteError("ssh %s 执行失败: %s" % (host, e))
    return p.returncode, p.stdout, p.stderr


_MISSING_MARK = "___PDNS_ADMIN_MISSING___"
_SPLIT_MARK = "___PDNS_ADMIN_SPLIT___"


def _ssh_read(host, path, timeout=15):
    rc, out, err = _ssh_exec(host, "cat -- %s" % shlex.quote(path), timeout=timeout)
    if rc != 0:
        raise RemoteError("%s@remote 读取失败: %s" % (path, (err or b"").decode("utf-8", "replace").strip() or ("exit %d" % rc)))
    return out


def _ssh_read_and_stat(host, path, timeout=15):
    """One ssh round trip for BOTH mtime and content -- webadmin.py's GET
    routes need both on every page load/refresh; two sequential ssh calls
    would double the (already user-visible) page-load latency for no
    reason. -> (content_bytes_or_None, mtime_float_or_None)."""
    q = shlex.quote(path)
    cmd = "stat -c %%Y -- %s 2>/dev/null || echo %s; echo %s; cat -- %s" % (
        q, _MISSING_MARK, _SPLIT_MARK, q)
    rc, out, err = _ssh_exec(host, cmd, timeout=timeout)
    marker = ("\n" + _SPLIT_MARK + "\n").encode("utf-8")
    if marker not in out:
        raise RemoteError("%s@remote 读取失败(意外输出): %s" % (
            path, (err or b"").decode("utf-8", "replace").strip() or ("exit %d" % rc)))
    stat_part, _, content = out.partition(marker)
    stat_text = stat_part.decode("utf-8", "replace").strip()
    mtime = None if stat_text == _MISSING_MARK else (float(stat_text) if stat_text else None)
    if mtime is None:
        return None, None
    return content, mtime


def _ssh_exists_stat(host, path, timeout=10):
    """-> (exists, mtime_float_or_None, mode_int). Single round trip."""
    rc, out, err = _ssh_exec(
        host, "stat -c '%%Y %%a' -- %s 2>/dev/null || echo MISSING" % shlex.quote(path), timeout=timeout)
    text = out.decode("utf-8", "replace").strip()
    if rc != 0 or text == "MISSING" or not text:
        return False, None, 0o644
    try:
        mt, mode = text.split()
        return True, float(mt), int(mode, 8)
    except ValueError:
        return False, None, 0o644


def stat_mtime(path, host=None):
    """Single mtime lookup, local or remote -- used by webadmin.py for the
    same base_mtime staleness guard the nft_route.json endpoints already
    use. Remote mtime is integer-second precision (`stat -c %Y`); the
    existing staleness comparisons already tolerate sub-second slop, so
    this is a drop-in equivalent to local os.stat().st_mtime."""
    if host:
        exists, mt, _ = _ssh_exists_stat(host, path)
        return mt if exists else None
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def _ssh_write_atomic(host, path, data, backup=True, timeout=20):
    """2 ssh round trips total (stat, then a single chained write+finalize
    command) rather than 4 -- every save from the UI is a human waiting on
    it, and each extra round trip is a full ssh handshake."""
    exists, _, mode = _ssh_exists_stat(host, path, timeout=timeout)
    mode = mode or 0o644
    tmp = "%s.tmp.%d" % (path, os.getpid())
    write_cmd = "(cat > %s && chmod %o -- %s && mv -f -- %s %s) || (rm -f -- %s; exit 1)" % (
        shlex.quote(tmp), mode, shlex.quote(tmp), shlex.quote(tmp), shlex.quote(path), shlex.quote(tmp))
    if backup and exists:
        # best-effort: a failed backup must not block the real write
        cmd = "cp -f -- %s %s.bak 2>/dev/null; %s" % (shlex.quote(path), shlex.quote(path), write_cmd)
    else:
        cmd = write_cmd
    rc, out, err = _ssh_exec(host, cmd, input_bytes=data, timeout=timeout)
    if rc != 0:
        raise RemoteError("%s@remote 写入失败: %s" % (path, (err or b"").decode("utf-8", "replace").strip() or ("exit %d" % rc)))


# ---------------------------------------------------------------------------
# config load / save (same atomic-write-through-realpath shape as
# iface_bind.save_config: deployed configs are often symlinks -- local path
# only, ssh writes are already atomic via tmp+mv on the remote filesystem)
# ---------------------------------------------------------------------------

def load_config(path, host=None):
    if host:
        return json.loads(_ssh_read(host, path).decode("utf-8"))
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_config_with_mtime(path, host=None):
    """(config, mtime) in ONE remote round trip when host is set (webadmin's
    GET route needs both on every load; two separate ssh calls would double
    page-load latency for nothing). Raises FileNotFoundError-ish RemoteError
    if the remote path doesn't exist (mirrors local open() raising)."""
    if host:
        content, mtime = _ssh_read_and_stat(host, path)
        if content is None:
            raise RemoteError("%s@%s 不存在" % (path, host))
        return json.loads(content.decode("utf-8")), mtime
    cfg = load_config(path)
    try:
        mt = os.stat(path).st_mtime
    except OSError:
        mt = None
    return cfg, mt


def save_config(path, cfg, backup=True, host=None):
    cfg = dict(cfg)
    cfg["rules"] = normalize_rules(cfg.get("rules") or {})
    text = json.dumps(cfg, ensure_ascii=False, indent=3)
    json.loads(text)  # round-trip validation before touching the real file
    if host:
        _ssh_write_atomic(host, path, (text + "\n").encode("utf-8"), backup=backup)
        return cfg
    real = os.path.realpath(path)
    try:
        mode = os.stat(real).st_mode & 0o777
    except OSError:
        mode = 0o644
    if backup and os.path.exists(real):
        try:
            with open(real, "r", encoding="utf-8") as f:
                old = f.read()
            with open(real + ".bak", "w", encoding="utf-8") as f:
                f.write(old)
        except OSError:
            pass
    d = os.path.dirname(os.path.abspath(real)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".pdns-recursor.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, real)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return cfg


def normalize_rules(rules):
    """Auto-prefix domain keys missing the leading dot (the one class of bug
    that's completely silent at runtime -- the rule just never matches real
    traffic). 'default' and '.' pass through unchanged."""
    out = {}
    for key, rulelist in (rules or {}).items():
        nk = key
        if key not in ("default", ".") and not key.startswith("."):
            nk = "." + key
        if nk in out:
            out[nk] = out[nk] + rulelist
        else:
            out[nk] = rulelist
    return out


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def validate_config(cfg):
    """Return list of human-readable problems (empty == OK). Cross-checks
    every forwarder_id/rc_id/src_group_id reference actually resolves --
    this is the class of bug that's otherwise invisible until the rule
    silently falls through to 'default' at query time."""
    errors = []
    if not isinstance(cfg, dict):
        return ["config 必须是 JSON object"]
    forwarders = cfg.get("forwarders") or {}
    source_group = cfg.get("source_group") or {}
    result_group = cfg.get("result_group") or {}
    rules = cfg.get("rules") or {}

    for section, name in ((forwarders, "forwarders"), (source_group, "source_group"),
                          (result_group, "result_group"), (rules, "rules")):
        if not isinstance(section, dict):
            errors.append("%s 必须是 object" % name)

    for fid, val in forwarders.items():
        if not isinstance(val, str) or not val.strip():
            errors.append("forwarders[%s] 必须是非空字符串 (host:port)" % fid)

    for sid, cidrs in source_group.items():
        if not isinstance(cidrs, list) or not cidrs:
            errors.append("source_group[%s] 必须是非空 CIDR 列表" % sid)
            continue
        for c in cidrs:
            try:
                ipaddress.ip_network(str(c), strict=False)
            except ValueError:
                errors.append("source_group[%s]: 无效 CIDR %r" % (sid, c))

    for rid, records in result_group.items():
        if not isinstance(records, list) or not records:
            errors.append("result_group[%s] 必须是非空记录列表" % rid)
            continue
        for i, rec in enumerate(records):
            if not isinstance(rec, dict) or not rec.get("type") or rec.get("value") in (None, ""):
                errors.append("result_group[%s][%d] 需要 type/value" % (rid, i))

    for domain, rulelist in rules.items():
        if domain != "default" and domain != "." and not str(domain).startswith("."):
            errors.append("rules[%s]: 域名 key 缺少前导点，实际只会匹配裸域名精确查询，"
                          "对子域名永远不生效（保存时会自动补成 '.%s'）" % (domain, domain))
        if not isinstance(rulelist, list) or not rulelist:
            errors.append("rules[%s] 必须是非空规则列表" % domain)
            continue
        for i, r in enumerate(rulelist):
            if not isinstance(r, dict):
                errors.append("rules[%s][%d] 必须是 object" % (domain, i))
                continue
            action = r.get("action")
            if action not in RESERVED_ACTIONS:
                errors.append("rules[%s][%d]: action 必须是 forwarder/result，实际 %r" % (domain, i, action))
                continue
            if action == "forwarder":
                fid = str(r.get("forwarder_id"))
                if fid not in forwarders:
                    errors.append("rules[%s][%d]: forwarder_id %r 不存在" % (domain, i, r.get("forwarder_id")))
            else:
                rid = str(r.get("rc_id"))
                if rid not in result_group:
                    errors.append("rules[%s][%d]: rc_id %r 不存在" % (domain, i, r.get("rc_id")))
            sgid = r.get("src_group_id")
            if sgid is not None and str(sgid) not in source_group:
                errors.append("rules[%s][%d]: src_group_id %r 不存在" % (domain, i, sgid))
    return errors


# ---------------------------------------------------------------------------
# poison list (plain text, one IP per line)
# ---------------------------------------------------------------------------

def load_poison_list(path, host=None):
    if host:
        try:
            raw = _ssh_read(host, path)
        except RemoteError:
            return []
        return [line.strip() for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return []


def load_poison_list_with_mtime(path, host=None):
    """(ips, mtime) in ONE remote round trip -- same rationale as
    load_config_with_mtime. Missing remote file -> ([], None), matching
    load_poison_list's existing "missing = empty" local behavior."""
    if host:
        content, mtime = _ssh_read_and_stat(host, path)
        if content is None:
            return [], None
        ips = [line.strip() for line in content.decode("utf-8", "replace").splitlines() if line.strip()]
        return ips, mtime
    ips = load_poison_list(path)
    try:
        mt = os.stat(path).st_mtime
    except OSError:
        mt = None
    return ips, mt


def save_poison_list(path, ips, backup=True, host=None):
    clean = []
    seen = set()
    for ip in ips:
        ip = str(ip).strip()
        if not ip or ip in seen:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("无效 IP: %r" % ip)
        seen.add(ip)
        clean.append(ip)
    text = "\n".join(clean) + ("\n" if clean else "")
    if host:
        _ssh_write_atomic(host, path, text.encode("utf-8"), backup=backup)
        return clean
    real = os.path.realpath(path)
    try:
        mode = os.stat(real).st_mode & 0o777
    except OSError:
        mode = 0o644
    if backup and os.path.exists(real):
        try:
            with open(real, "r", encoding="utf-8") as f:
                old = f.read()
            with open(real + ".bak", "w", encoding="utf-8") as f:
                f.write(old)
        except OSError:
            pass
    d = os.path.dirname(os.path.abspath(real)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".dns_posion_list.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, real)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return clean


# ---------------------------------------------------------------------------
# runtime reload
# ---------------------------------------------------------------------------

def reload_recursor(rec_control_bin="rec_control", timeout=5, run=None, host=None):
    """Best-effort `rec_control reload-lua-script`, local or (if `host` is
    set) over ssh. Only reloads the Lua script side (forwarders/
    source_group/result_group/rules) -- PowerDNS Recursor's own
    lua-maintenance-interval already auto-picks-up content changes within a
    second, so this is for "make it happen right now" rather than being
    load-bearing. The poison list lives in a separate process
    (pdns-forwarder.py) with its own reload mechanism (SIGHUP + periodic
    mtime check), not covered here. `run` is injectable for tests."""
    runner = run or subprocess.run
    if host:
        argv = _ssh_prefix(host) + ["%s reload-lua-script" % rec_control_bin]
    else:
        argv = [rec_control_bin, "reload-lua-script"]
    try:
        p = runner(argv, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        return {"ok": p.returncode == 0, "returncode": p.returncode, "output": out.strip()}
    except FileNotFoundError:
        return {"ok": False, "error": "%s 未找到 (未安装/不在 PATH)" % argv[0]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "%s 超时 (%ss)" % (argv[0], timeout)}
    except OSError as e:
        return {"ok": False, "error": str(e)}
