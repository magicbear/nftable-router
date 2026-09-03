#!/usr/bin/env python3
"""Offline tests for pdns_admin.py. No root, no pdns-recursor/redis. Run:
python3 test_pdns_admin.py"""

import copy
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pdns_admin as pa

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, ("-> " + detail) if detail else ""))


BASE_CFG = {
    "source_group": {"1": ["172.16.211.0/24"]},
    "result_group": {"1": [{"type": "A", "value": "10.66.32.12", "ttl": 15}]},
    "forwarders": {"24": "223.5.5.5:53", "29": "8.8.8.8,8.8.4.4:53"},
    "rules": {
        ".youtube.com.": [{"action": "forwarder", "forwarder_id": "29"}],
        "default": [{"action": "forwarder", "forwarder_id": "24"}],
    },
}


def test_normalize_rules():
    print("[1] normalize_rules: auto-prefix missing leading dot")
    rules = {
        "youtube.com.": [{"action": "forwarder", "forwarder_id": "29"}],
        ".dropbox.com.": [{"action": "forwarder", "forwarder_id": "29"}],
        "default": [{"action": "forwarder", "forwarder_id": "24"}],
        ".": [{"action": "forwarder", "forwarder_id": "24"}],
    }
    out = pa.normalize_rules(rules)
    check("bare domain got leading dot", ".youtube.com." in out and "youtube.com." not in out)
    check("already-correct key untouched", ".dropbox.com." in out)
    check("'default' untouched", "default" in out)
    check("'.' untouched", "." in out)

    # collision: normalizing 'x.com.' and pre-existing '.x.com.' must MERGE,
    # not silently drop one -- losing rules is worse than a duplicate list
    merged = pa.normalize_rules({"x.com.": [{"action": "forwarder", "forwarder_id": "29"}],
                                 ".x.com.": [{"action": "forwarder", "forwarder_id": "24"}]})
    check("colliding normalized keys merge (both rule lists survive)",
          len(merged[".x.com."]) == 2)


def test_validate_config_ok():
    print("[2] validate_config: clean config passes")
    errors = pa.validate_config(BASE_CFG)
    check("no errors", errors == [], str(errors))


def test_validate_config_catches_bugs():
    print("[3] validate_config: catches dangling refs and missing dot")
    cfg = copy.deepcopy(BASE_CFG)
    cfg["rules"]["youtube.com."] = [{"action": "forwarder", "forwarder_id": "29"}]  # missing dot
    cfg["rules"][".ghost.com."] = [{"action": "forwarder", "forwarder_id": "999"}]  # bad ref
    cfg["rules"][".bad-action.com."] = [{"action": "block"}]
    cfg["rules"][".scoped.com."] = [{"action": "forwarder", "forwarder_id": "29", "src_group_id": "9"}]
    errors = pa.validate_config(cfg)
    check("missing leading dot flagged", any("缺少前导点" in e for e in errors))
    check("dangling forwarder_id flagged", any("999" in e for e in errors))
    check("bad action flagged", any("block" in e for e in errors))
    check("dangling src_group_id flagged", any("src_group_id" in e and "9" in e for e in errors))

    cfg2 = copy.deepcopy(BASE_CFG)
    cfg2["source_group"]["bad"] = ["not-a-cidr"]
    check("invalid CIDR flagged", any("CIDR" in e for e in pa.validate_config(cfg2)))

    cfg3 = copy.deepcopy(BASE_CFG)
    cfg3["result_group"]["bad"] = [{"type": "A"}]  # missing value
    check("result_group missing value flagged", any("result_group[bad]" in e for e in pa.validate_config(cfg3)))


def test_config_save_load_roundtrip():
    print("[4] save_config/load_config: atomic write, .bak, normalizes on save")
    d = tempfile.mkdtemp()
    path = os.path.join(d, "pdns-recursor.json")
    cfg = copy.deepcopy(BASE_CFG)
    cfg["rules"]["steamcommunity.com."] = [{"action": "forwarder", "forwarder_id": "29"}]
    saved = pa.save_config(path, cfg)
    check("save normalized the bare key before writing",
          ".steamcommunity.com." in saved["rules"] and "steamcommunity.com." not in saved["rules"])
    check("file on disk is also normalized",
          ".steamcommunity.com." in pa.load_config(path)["rules"])
    check("no .bak on first save (nothing to back up)", not os.path.exists(path + ".bak"))

    cfg2 = pa.load_config(path)
    cfg2["forwarders"]["99"] = "1.1.1.1:53"
    pa.save_config(path, cfg2)
    check(".bak created on second save", os.path.exists(path + ".bak"))
    check(".bak holds the PREVIOUS content", "99" not in pa.load_config(path + ".bak")["forwarders"])
    check("current file holds the NEW content", "99" in pa.load_config(path)["forwarders"])

    # symlink safety: save_config must write through the real target, not
    # detach the link (same invariant iface_bind.save_config enforces)
    real_dir = tempfile.mkdtemp()
    real_path = os.path.join(real_dir, "real.json")
    pa.save_config(real_path, BASE_CFG)
    link_path = os.path.join(d, "linked.json")
    os.symlink(real_path, link_path)
    cfg3 = pa.load_config(link_path)
    cfg3["forwarders"]["55"] = "5.5.5.5:53"
    pa.save_config(link_path, cfg3)
    check("symlink preserved after save", os.path.islink(link_path))
    check("real target file got the write", "55" in pa.load_config(real_path)["forwarders"])


def test_poison_list_roundtrip():
    print("[5] poison list: load/save, dedup, invalid IP rejected")
    d = tempfile.mkdtemp()
    path = os.path.join(d, "dns_posion_list.txt")
    check("missing file loads as empty list (no crash)", pa.load_poison_list(path) == [])

    saved = pa.save_poison_list(path, ["1.2.3.4", "5.6.7.8", "1.2.3.4", " 9.9.9.9 "])
    check("dedup applied", saved == ["1.2.3.4", "5.6.7.8", "9.9.9.9"])
    check("file round-trips", pa.load_poison_list(path) == saved)

    try:
        pa.save_poison_list(path, ["not-an-ip"])
        check("invalid IP rejected", False)
    except ValueError as e:
        check("invalid IP rejected", "not-an-ip" in str(e))
    check("rejected save did NOT touch the file (still old content)",
          pa.load_poison_list(path) == saved)


def test_reload_recursor():
    print("[6] reload_recursor: injectable runner, error paths")
    class FakeResult:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    calls = []
    def ok_runner(argv, **kw):
        calls.append(argv)
        return FakeResult(0, "ok\n")
    r = pa.reload_recursor(run=ok_runner)
    check("success path", r["ok"] is True and calls[0] == ["rec_control", "reload-lua-script"])

    def fail_runner(argv, **kw):
        return FakeResult(1, "", "no such script")
    r2 = pa.reload_recursor(run=fail_runner)
    check("nonzero rc -> ok False, output captured", r2["ok"] is False and "no such script" in r2["output"])

    def missing_runner(argv, **kw):
        raise FileNotFoundError()
    r3 = pa.reload_recursor(run=missing_runner)
    check("missing binary -> clear error, no traceback", r3["ok"] is False and "error" in r3)

    import subprocess as sp
    def timeout_runner(argv, **kw):
        raise sp.TimeoutExpired(argv, 5)
    r4 = pa.reload_recursor(run=timeout_runner)
    check("timeout -> clear error", r4["ok"] is False and "超时" in r4["error"])


# ---------------------------------------------------------------------------
# SSH transport: no real network/sshd needed. Every ssh helper in
# pdns_admin.py builds a single remote-shell command string and hands it to
# `ssh ... host '<cmd>'`; here we intercept subprocess.run at the module
# level and, instead of faking a filesystem in Python, run that EXACT
# command string through a REAL local shell (`sh -c`) -- this exercises
# the actual quoting/chaining pdns_admin.py generates (cat >, chmod && mv,
# stat -c format, cp .bak) against real coreutils, not a hand-rolled mock.
# ---------------------------------------------------------------------------

def _install_fake_ssh():
    real_run = subprocess.run
    calls = []
    def fake_run(argv, input=None, capture_output=True, timeout=None, text=False, **kw):
        calls.append(argv)
        assert argv[0] == "ssh", "expected an ssh invocation, got %r" % (argv,)
        remote_cmd = argv[-1]
        return real_run(["sh", "-c", remote_cmd], input=input, capture_output=True,
                        timeout=timeout, text=text)
    pa.subprocess.run = fake_run
    return calls


def _restore_ssh(real_run):
    pa.subprocess.run = real_run


def test_ssh_prefix_parsing():
    print("[7] _ssh_prefix: host[:port] parsing, including tricky ipv6 cases")
    def target(argv):
        return argv[-1], (argv[argv.index("-p") + 1] if "-p" in argv else None)
    check("plain host, no port", target(pa._ssh_prefix("root@1.2.3.4")) == ("root@1.2.3.4", None))
    check("host:port extracted", target(pa._ssh_prefix("root@1.2.3.4:2222")) == ("root@1.2.3.4", "2222"))
    check("bracketed ipv6:port extracted",
          target(pa._ssh_prefix("root@[2001:db8::1]:2222")) == ("root@[2001:db8::1]", "2222"))
    check("bracketed ipv6, no port untouched",
          target(pa._ssh_prefix("root@[2001:db8::1]")) == ("root@[2001:db8::1]", None))
    check("bare (unbracketed) ipv6 not mis-split on its own colons",
          target(pa._ssh_prefix("root@::1")) == ("root@::1", None))
    check("BatchMode always set", "-o" in pa._ssh_prefix("h") and "BatchMode=yes" in pa._ssh_prefix("h"))


def test_ssh_config_roundtrip():
    print("[8] ssh transport: config load/save/mtime round-trip via a real local shell")
    real_run = subprocess.run
    calls = _install_fake_ssh()
    try:
        d = tempfile.mkdtemp()
        path = os.path.join(d, "pdns-recursor.json")
        host = "fake-host"   # never actually dialed -- fake_run reroutes to sh -c

        check("missing remote file -> mtime None, no crash", pa.stat_mtime(path, host=host) is None)

        cfg = copy.deepcopy(BASE_CFG)
        cfg["rules"]["youtube.com."] = [{"action": "forwarder", "forwarder_id": "29"}]
        saved = pa.save_config(path, cfg, host=host)
        check("remote save normalized the bare key", ".youtube.com." in saved["rules"])
        check("remote file actually exists now", os.path.exists(path))
        check("remote load matches what was saved", pa.load_config(path, host=host) == saved)
        check("mtime now resolvable", pa.stat_mtime(path, host=host) is not None)
        check("no .bak yet (first write)", not os.path.exists(path + ".bak"))
        check("every ssh call actually went through ssh argv shape",
              all(c[0] == "ssh" and "BatchMode=yes" in c for c in calls))

        cfg2 = pa.load_config(path, host=host)
        cfg2["forwarders"]["99"] = "1.1.1.1:53"
        pa.save_config(path, cfg2, host=host)
        check(".bak created on second remote save", os.path.exists(path + ".bak"))
        check(".bak holds the PREVIOUS content", "99" not in pa.load_config(path + ".bak").get("forwarders", {}))
        check("current remote file holds the NEW content", "99" in pa.load_config(path, host=host)["forwarders"])

        # file mode is preserved across the remote tmp+chmod+mv dance
        os.chmod(path, 0o640)
        cfg3 = pa.load_config(path, host=host)
        pa.save_config(path, cfg3, host=host, backup=False)
        check("file mode preserved through remote write", (os.stat(path).st_mode & 0o777) == 0o640)

        # combined load+mtime: ONE ssh round trip instead of two (halves
        # page-load latency to a remote host -- this is the actual point)
        calls.clear()
        cfg4, mt4 = pa.load_config_with_mtime(path, host=host)
        check("combined load used exactly ONE ssh call", len(calls) == 1, str(calls))
        check("combined load returns matching config", cfg4 == pa.load_config(path))
        check("combined load returns a usable mtime", mt4 is not None and mt4 == pa.stat_mtime(path, host=host))

        missing_path = os.path.join(d, "does-not-exist.json")
        try:
            pa.load_config_with_mtime(missing_path, host=host)
            check("combined load on missing remote file raises", False)
        except pa.RemoteError:
            check("combined load on missing remote file raises", True)
    finally:
        _restore_ssh(real_run)


def test_ssh_poison_list_roundtrip():
    print("[9] ssh transport: poison list load/save round-trip")
    real_run = subprocess.run
    calls = _install_fake_ssh()
    try:
        d = tempfile.mkdtemp()
        path = os.path.join(d, "dns_posion_list.txt")
        host = "fake-host"
        check("missing remote poison list -> empty, no crash", pa.load_poison_list(path, host=host) == [])
        saved = pa.save_poison_list(path, ["1.2.3.4", "1.2.3.4", " 5.6.7.8 "], host=host)
        check("dedup applied over ssh path too", saved == ["1.2.3.4", "5.6.7.8"])
        check("remote load matches", pa.load_poison_list(path, host=host) == saved)

        calls.clear()
        ips2, mt2 = pa.load_poison_list_with_mtime(path, host=host)
        check("combined poison load matches", ips2 == saved)
        check("combined poison load returns usable mtime", mt2 is not None)
        check("combined poison load used exactly ONE ssh call", len(calls) == 1, str(calls))
        missing2, mtm = pa.load_poison_list_with_mtime(os.path.join(d, "nope.txt"), host=host)
        check("combined poison load on missing file -> ([], None)", missing2 == [] and mtm is None)
        try:
            pa.save_poison_list(path, ["not-an-ip"], host=host)
            check("invalid IP rejected before any ssh write", False)
        except ValueError:
            check("invalid IP rejected before any ssh write", True)
        check("rejected save left remote file untouched", pa.load_poison_list(path, host=host) == saved)
    finally:
        _restore_ssh(real_run)


def test_ssh_reload_and_errors():
    print("[10] ssh transport: reload_recursor over ssh, and ssh-level failure surfaces cleanly")
    real_run = subprocess.run
    calls = _install_fake_ssh()
    try:
        r = pa.reload_recursor(host="fake-host")
        check("reload argv is ssh + rec_control command",
              calls[-1][0] == "ssh" and calls[-1][-1] == "rec_control reload-lua-script")
        check("fake shell has no rec_control binary -> ok False, not a Python crash", r["ok"] is False)
    finally:
        _restore_ssh(real_run)

    # ssh itself unreachable/unauthorized (nonexistent local binary stands
    # in for "connection refused" / "permission denied") -> RemoteError,
    # not an uncaught exception, from the read/write helpers
    real_run2 = subprocess.run
    def unreachable_run(argv, **kw):
        raise FileNotFoundError("ssh binary not found (simulating unreachable host)")
    pa.subprocess.run = unreachable_run
    try:
        try:
            pa.load_config("/etc/powerdns/pdns-recursor.json", host="unreachable-host")
            check("unreachable ssh host raises RemoteError on read", False)
        except pa.RemoteError as e:
            check("unreachable ssh host raises RemoteError on read", "unreachable-host" in str(e))
    finally:
        pa.subprocess.run = real_run2


if __name__ == "__main__":
    for t in (test_normalize_rules, test_validate_config_ok, test_validate_config_catches_bugs,
              test_config_save_load_roundtrip, test_poison_list_roundtrip, test_reload_recursor,
              test_ssh_prefix_parsing, test_ssh_config_roundtrip, test_ssh_poison_list_roundtrip,
              test_ssh_reload_and_errors):
        t()
    print("\n==== %d passed, %d failed ====" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
