#!/usr/bin/env python
"""
run_tests.py - cross-platform test runner for the p2pd-family repos.

Usage:
    python run_tests.py <repo> <python_version> <test_name>

    repo           : aionetiface | namebump | sidewire | p2pd
    python_version : 3.5.10 | 3.8.6 | 3.9.13 | ... | lowest | middle | highest | random
    test_name      : test_unit | test_pipe | ... | all

Examples:
    python run_tests.py p2pd 3.8.6 all
    python run_tests.py aionetiface 3.5.10 test_pipe
"""

import argparse
import datetime
import glob
import json
import multiprocessing
import os
import queue
import random
import re
import shutil
import subprocess
import sys
import threading
import time

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.10"

REPO_BRANCHES = {
    "aionetiface": "ai_experiment",
    "p2pd":        "ai_experiment",
    "namebump":    "main",
    "sidewire":    "main",
}

ALL_REPOS       = ["aionetiface", "namebump", "sidewire", "p2pd"]
UNINSTALL_ORDER = ["p2pd", "namebump", "sidewire", "aionetiface"]
INSTALL_ORDER   = ["aionetiface", "namebump", "sidewire", "p2pd"]

LOG_BASE_DIR = os.path.join(os.path.expanduser("~"), "test_out")
PING_INTERVAL   = 30   # seconds between ping file updates
TEST_TIMEOUT    = 300  # 5 minutes per individual test
DEFAULT_WORKERS = 4    # fallback for 1-2 vCPU machines; 15 saturates WMIC on single-core Windows

INSTALL_SUCCESS_RE = re.compile(
    r"(successfully installed|already satisfied)",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Search paths — ordered most-common first; script's own parent dir is first
# so sibling checkouts are found automatically.
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

REPO_SEARCH_DIRS = [
    SCRIPT_DIR,
    os.path.expanduser("~/projects"),
    r"C:\Users\x\projects",
    r"C:\Users\matth\projects",
    r"C:\Users\matthew\projects",
    r"C:\Documents and Settings\matthew\projects",
    r"C:\Documents and Settings\x\projects",
    r"C:\Users\Administrator\projects",
    "/home/x/projects",
    "/Users/xx/projects",
    "/data/data/com.termux/files/home/projects",
    "/root/projects",
]
# Strict projects/-only policy: do NOT search bare home directories
# (~, C:\Users\<u>\, C:\Documents and Settings\<u>\). A stale clone
# at ~/aionetiface (or equivalent) would otherwise be picked up by
# find_repo, sync_repos updates only the projects/ checkout, and the
# Python interpreter ends up importing the stale code while the test
# runner believes the fresh code is being tested. Single canonical
# location prevents the divergence.

PYENV_SEARCH_DIRS = [
    os.path.join(os.path.expanduser("~"), ".pyenv", "pyenv-win", "versions"),
    os.path.join(os.path.expanduser("~"), ".pyenv", "versions"),
    r"C:\Users\x\.pyenv\pyenv-win\versions",
    r"C:\Users\matth\.pyenv\pyenv-win\versions",
    r"C:\Users\matthew\.pyenv\pyenv-win\versions",
    r"C:\Users\Administrator\.pyenv\pyenv-win\versions",
    "/home/x/.pyenv/versions",
    "/Users/xx/.pyenv/versions",
    "/root/.pyenv/versions",
]

# Non-pyenv Python installations (e.g. Windows XP).
PYTHON_DIRECT = [
    r"C:\py3\python.exe",
]

# ─────────────────────────────────────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────────────────────────────────────

def sanitize(s):
    """Strip characters not in [a-zA-Z0-9-_.]."""
    return re.sub(r"[^a-zA-Z0-9\-_.]", "", s)

def find_repo(name):
    """Return the directory of repo `name`, or None if not found."""
    for base in REPO_SEARCH_DIRS:
        candidate = os.path.join(base, name)
        if os.path.isdir(os.path.join(candidate, ".git")):
            return candidate
    return None

def find_python(version):
    """Return the path to the Python executable for the given pyenv version.

    If version is an absolute path that exists, it is returned directly.
    """
    # Absolute path handed in directly.
    if os.path.isabs(version) and os.path.isfile(version):
        return version
    for base in PYENV_SEARCH_DIRS:
        for subdir in ("", "bin"):
            for exe in ("python.exe", "python"):
                p = os.path.join(base, version, subdir, exe)
                if os.path.isfile(p):
                    return p
    for p in PYTHON_DIRECT:
        if os.path.isfile(p):
            return p
    # Try system python from PATH (machines without pyenv).
    for candidate in ("python", "python3"):
        try:
            out = subprocess.check_output(
                [candidate, "--version"],
                stderr=subprocess.STDOUT,
            ).decode("utf-8", "replace").strip()
            if out.startswith("Python 3"):
                return candidate
        except (OSError, subprocess.CalledProcessError):
            pass
    # Last resort: the interpreter running this script.
    return sys.executable

def list_pyenv_versions():
    """Return pyenv Python version strings >= 3.5 found on this machine, sorted ascending."""
    seen = set()
    for base in PYENV_SEARCH_DIRS:
        if not os.path.isdir(base):
            continue
        try:
            entries = os.listdir(base)
        except OSError:
            continue
        for entry in entries:
            for subdir in ("", "bin"):
                for exe in ("python.exe", "python"):
                    if os.path.isfile(os.path.join(base, entry, subdir, exe)):
                        seen.add(entry)
                        break
    versioned = []
    for v in seen:
        parts = v.split(".")
        try:
            t = tuple(int(x) for x in parts)
        except ValueError:
            continue
        if len(t) >= 2 and t >= (3, 5):
            versioned.append((t, v))
    versioned.sort()
    return [v for _, v in versioned]

def python_works(exe_path):
    """Return True if exe_path runs '--version' successfully within 5 seconds."""
    try:
        r = subprocess.run(
            [exe_path, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False

def resolve_python_version(spec):
    """Resolve 'lowest'/'middle'/'highest'/'random'/'system' to an actual version string."""
    if spec == "system":
        return sys.executable
    if spec not in ("lowest", "middle", "highest", "random"):
        return spec
    available = list_pyenv_versions()
    if not available:
        # No pyenv — fall back to C:\py3, PATH python, or sys.executable.
        return find_python("no_pyenv_fallback")
    mid = len(available) // 2
    if spec == "lowest":
        primary, rest = available[0], available[1:]
    elif spec == "highest":
        primary, rest = available[-1], list(reversed(available[:-1]))
    elif spec == "random":
        primary = random.choice(available)
        rest = [v for v in available if v != primary]
    else:  # middle — on fallback try versions nearest the centre first
        primary = available[mid]
        below = list(reversed(available[:mid]))
        above = available[mid + 1:]
        rest = [v for p in zip(below, above) for v in p]
        if len(below) > len(above):
            rest += below[len(above):]
        elif len(above) > len(below):
            rest += above[len(below):]
    for version in [primary] + list(rest):
        exe = find_python(version)
        if python_works(exe):
            return version
    return find_python("no_pyenv_fallback")

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def append_log(path, text):
    with open(path, "a") as fh:
        fh.write("[{}] {}\n".format(now(), text))

def make_run_dir(repo, version_arg, timestamp):
    """Return (and create) the per-run log directory:
    LOG_BASE_DIR/<repo>/<version_arg>/<timestamp>/
    where version_arg is the user-supplied alias (lowest/middle/highest/random)
    or an exact version string."""
    d = os.path.join(
        LOG_BASE_DIR,
        sanitize(repo),
        sanitize(version_arg),
        sanitize(timestamp),
    )
    if not os.path.isdir(d):
        os.makedirs(d)
    return d

# ─────────────────────────────────────────────────────────────────────────────
# Subprocess runner
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd, cwd=None, log_path=None, timeout=None, env_extra=None):
    """
    Run cmd and capture stdout+stderr.  Append output to log_path if given.
    env_extra overlays additional env vars onto os.environ for the child.
    Returns (returncode, output_text).
    """
    cmd_str = " ".join(str(c) for c in cmd)
    if log_path:
        append_log(log_path, "$ " + cmd_str)

    if env_extra:
        merged_env = os.environ.copy()
        merged_env.update(env_extra)
    else:
        merged_env = None

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
            env=merged_env,
        )
    except Exception as exc:
        msg = "[ERROR launching '{}': {}]\n".format(cmd_str, exc)
        if log_path:
            with open(log_path, "a") as fh:
                fh.write(msg)
        return -1, msg

    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        leftover = proc.communicate()[0] or ""
        out = leftover + "\n[TIMED OUT after {}s]\n".format(timeout)
        if log_path:
            with open(log_path, "a") as fh:
                fh.write(out)
        return -1, out

    if log_path:
        with open(log_path, "a") as fh:
            fh.write(out)
    return proc.returncode, out

def get_site_packages(python_exe, setup_log):
    """Return the site-packages directory used by python_exe, or None if it can't be determined."""
    rc, out = run_cmd(
        [
            python_exe, "-c",
            "import sysconfig,sys;sys.stdout.write(sysconfig.get_paths()['purelib'])",
        ],
        log_path=setup_log,
    )
    if rc != 0:
        append_log(setup_log, "WARNING: could not resolve site-packages for {}".format(python_exe))
        return None
    path = out.strip()
    if not path or not os.path.isdir(path):
        append_log(setup_log, "WARNING: resolved site-packages does not exist: {!r}".format(path))
        return None
    return path


def purge_site_packages_residue(site_packages, pkg, setup_log):
    """Remove leftover <pkg>* dirs/files and .pth references after pip uninstall.

    Targets:
      * <site-packages>/<pkg>/             -- module dir from a wheel install
      * <site-packages>/<pkg>-*.dist-info/ -- pip metadata
      * <site-packages>/<pkg>-*.egg-info/  -- legacy setuptools metadata
      * <site-packages>/<pkg>.egg-link     -- editable install pointer
      * <site-packages>/<pkg>-*.egg/       -- old-style installed egg
      * any line in <site-packages>/*.pth referencing the package's
        path (handles both editable installs and easy_install entries)
    """
    if not site_packages or not os.path.isdir(site_packages):
        return

    pkg_lower = pkg.lower()
    for entry in os.listdir(site_packages):
        entry_lower = entry.lower()
        full = os.path.join(site_packages, entry)

        # Case-insensitive exact-name dir match (Windows fs is
        # case-insensitive; pip may write either casing depending on
        # version).
        if entry_lower == pkg_lower and os.path.isdir(full):
            rm_path(full, setup_log, "module dir")
            continue

        # Metadata + egg patterns: prefix match with a delimiter so we
        # don't accidentally nuke an unrelated package whose name
        # starts with this one.
        for suffix in (".dist-info", ".egg-info", ".egg"):
            if entry_lower.startswith(pkg_lower + "-") and entry_lower.endswith(suffix):
                rm_path(full, setup_log, suffix.lstrip("."))
                break

        # editable install pointer
        if entry_lower == pkg_lower + ".egg-link":
            rm_path(full, setup_log, "egg-link")

    # Clean .pth files: remove lines that reference the package's
    # source path. Editable installs append a path line like
    # 'C:\\Users\\matth\\projects\\aionetiface\\src' to a .pth file
    # which keeps the import resolving even after pip uninstall fails
    # to remove the .pth entry.
    for entry in os.listdir(site_packages):
        if not entry.endswith(".pth"):
            continue
        pth_path = os.path.join(site_packages, entry)
        try:
            with open(pth_path, "r") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        kept = [
            ln for ln in lines
            if pkg_lower not in ln.lower()
        ]
        if len(kept) != len(lines):
            try:
                with open(pth_path, "w") as fh:
                    fh.writelines(kept)
                append_log(
                    setup_log,
                    "purged {} line(s) referencing {} from {}".format(
                        len(lines) - len(kept), pkg, entry,
                    ),
                )
            except OSError:
                append_log(
                    setup_log,
                    "WARNING: could not rewrite {} to drop {} entries".format(
                        entry, pkg,
                    ),
                )


def rm_path(path, setup_log, label):
    """Remove a file or directory, logging the action."""
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        append_log(setup_log, "removed {} {}".format(label, path))
    except OSError as exc:
        append_log(
            setup_log,
            "WARNING: could not remove {} {}: {!r}".format(label, path, exc),
        )


SIBLING_NAMES = ("aionetiface", "namebump", "sidewire", "p2pd")


def strip_sibling_deps(repo_dir, setup_log):
    """Remove sibling entries from pyproject.toml / setup.py before pip install.

    Without this step, pip processes install_requires for each repo
    and resolves the sibling names by pulling the latest published
    wheels from PyPI / the local cache.  Those wheels land in
    site-packages where they shadow whichever editable install we
    set up against the projects/ checkout, depending on sys.path
    order.  We end up with a sweep that runs against a mix of
    editable-from-checkout for some siblings and stale-wheel-from-
    PyPI for others -- exactly the contamination class install_check
    exists to catch.

    Stripping the sibling lines from pyproject.toml + setup.py
    before pip install forces pip to skip them entirely.
    INSTALL_ORDER guarantees the siblings are already editable-
    installed in dependency order before any consumer is processed,
    so satisfying their import is not pip's job.

    The next setup_repos pass starts with `git reset --hard origin`,
    which restores the source files automatically -- so this rewrite
    is intentionally non-destructive across runs.  We do NOT touch
    third-party deps (ecdsa, ntplib, netifaces, aiomysql, ...).
    """
    for fname in ("pyproject.toml", "setup.py"):
        path = os.path.join(repo_dir, fname)
        if not os.path.isfile(path):
            continue
        try:
            with open(path) as fh:
                src = fh.read()
        except OSError:
            continue

        new = src
        for sib in SIBLING_NAMES:
            esc = re.escape(sib)
            # Multi-line list entry (pyproject.toml-style):
            #     "aionetiface",
            #     "aionetiface"
            new = re.sub(
                r'^\s*"' + esc + r'"\s*,?\s*\n',
                "",
                new,
                flags=re.MULTILINE,
            )
            # Inline list entry with trailing comma:
            #     install_requires=["aionetiface", "ecdsa"]
            new = re.sub(r'"' + esc + r'"\s*,\s*', "", new)
            # Inline list entry as last element (no trailing comma):
            #     install_requires=["ecdsa", "aionetiface"]
            new = re.sub(r',\s*"' + esc + r'"', "", new)

        if new != src:
            try:
                with open(path, "w") as fh:
                    fh.write(new)
                append_log(
                    setup_log,
                    "stripped sibling deps from {}".format(path),
                )
            except OSError as exc:
                append_log(
                    setup_log,
                    "WARNING: could not strip sibling deps from {}: {!r}".format(
                        path, exc,
                    ),
                )


# ─────────────────────────────────────────────────────────────────────────────
# Git + install
# ─────────────────────────────────────────────────────────────────────────────

def get_repo_shas(repo_dirs):
    """Return {repo_name: short_git_sha} for each repo dir, or '?' on failure."""
    shas = {}
    for name, d in repo_dirs.items():
        try:
            out = subprocess.check_output(
                ["git", "rev-parse", "--short=7", "HEAD"],
                cwd=d, stderr=subprocess.STDOUT,
            ).decode("utf-8", "replace").strip()
            shas[name] = out
        except (OSError, subprocess.CalledProcessError):
            shas[name] = "?"
    return shas


def setup_repos(python_exe, repo_dirs, setup_log):
    # 1. git fetch + reset --hard
    for name in ALL_REPOS:
        d = repo_dirs.get(name)
        if not d:
            append_log(setup_log, "SKIP git reset: {} not found".format(name))
            continue
        branch = REPO_BRANCHES.get(name, "main")
        append_log(setup_log, "--- git reset {} ({}) ---".format(name, branch))
        run_cmd(["git", "fetch", "origin"], cwd=d, log_path=setup_log)
        run_cmd(
            ["git", "reset", "--hard", "origin/{}".format(branch)],
            cwd=d, log_path=setup_log,
        )

    # 2. git pull
    for name in ALL_REPOS:
        d = repo_dirs.get(name)
        if not d:
            continue
        append_log(setup_log, "--- git pull {} ---".format(name))
        run_cmd(["git", "pull"], cwd=d, log_path=setup_log)

    # 3. Ensure wheel is available (required for --no-build-isolation on some Python versions).
    append_log(setup_log, "--- pip install wheel ---")
    run_cmd([python_exe, "-m", "pip", "install", "wheel"], log_path=setup_log)

    # 4. Aggressive uninstall (reverse dep order). Plain `pip uninstall`
    # is not enough on its own:
    #   * Some package metadata (.dist-info / .egg-info) survives a
    #     single uninstall pass when an older/newer install layered on
    #     top of a different one. A second uninstall removes the
    #     residual record.
    #   * Editable installs leave .pth files in site-packages whose
    #     entries point at the dev checkout. If a wheel install later
    #     puts a copy in site-packages too, the .pth entry can keep
    #     resolving the import to a stale path; we delete those lines.
    #   * Loose <pkg>* directories left in site-packages from a botched
    #     uninstall continue to satisfy `import <pkg>` even after pip
    #     reports no installation. We rm them outright.
    #   * pip's wheel cache occasionally serves an older sdist than the
    #     local checkout when the local version string didn't bump;
    #     purging the cache forces a fresh build off the working tree.
    site_packages = get_site_packages(python_exe, setup_log)
    for name in UNINSTALL_ORDER:
        append_log(setup_log, "--- pip uninstall {} (pass 1) ---".format(name))
        run_cmd(
            [python_exe, "-m", "pip", "uninstall", "-y", name],
            log_path=setup_log,
        )
        append_log(setup_log, "--- pip uninstall {} (pass 2) ---".format(name))
        run_cmd(
            [python_exe, "-m", "pip", "uninstall", "-y", name],
            log_path=setup_log,
        )
        if site_packages:
            purge_site_packages_residue(site_packages, name, setup_log)
    append_log(setup_log, "--- pip cache purge ---")
    run_cmd([python_exe, "-m", "pip", "cache", "purge"], log_path=setup_log)

    # 4. pip install (dep order)
    for name in INSTALL_ORDER:
        d = repo_dirs.get(name)
        if not d:
            append_log(setup_log, "SKIP install: {} not found".format(name))
            continue
        # Strip sibling entries from this repo's pyproject.toml /
        # setup.py before pip processes install_requires. INSTALL_ORDER
        # guarantees siblings are already editable-installed by the
        # time we reach a consumer, so leaving the deps in just gives
        # pip an excuse to pull a stale wheel from PyPI/cache that
        # shadows our editable install. Restored on next run by the
        # git reset --hard at the top of setup_repos.
        strip_sibling_deps(d, setup_log)

        append_log(setup_log, "--- pip install {} ---".format(name))
        rc, out = run_cmd(
            [
                python_exe, "-m", "pip", "install",
                "--no-build-isolation", "-e", ".",
            ],
            cwd=d, log_path=setup_log,
        )
        # pip < 10 does not support --no-build-isolation; retry without it.
        if rc != 0 and "no such option" in out.lower():
            append_log(setup_log, "retrying without --no-build-isolation (old pip)")
            rc, out = run_cmd(
                [python_exe, "-m", "pip", "install", "-e", "."],
                cwd=d, log_path=setup_log,
            )
        if INSTALL_SUCCESS_RE.search(out):
            append_log(setup_log, "OK: {} installed".format(name))
        else:
            append_log(
                setup_log,
                "WARNING: {} install may have failed (rc={})".format(name, rc),
            )

    # Strictly verify what python_exe actually imports for each
    # sibling. The install steps above can succeed (rc=0, "OK")
    # while leaving the import path broken: stale wheel in
    # site-packages shadows the editable checkout, an old clone
    # outside the expected root takes precedence on sys.path, etc.
    # When that happens, the test suite runs against stale code and
    # produces misleading verdicts. Failing here is loud, immediate,
    # and tells us exactly which sibling diverged.
    append_log(setup_log, "--- verify install (p2pd.install_check) ---")
    rc, out = run_cmd(
        [python_exe, "-m", "p2pd.install_check", "--strict"],
        log_path=setup_log,
    )
    if rc != 0:
        append_log(
            setup_log,
            "FATAL: sibling install verification failed (rc={}). "
            "Tests would run against stale/divergent code; aborting.".format(rc),
        )
        raise SystemExit(2)
    append_log(setup_log, "OK: sibling installs verified consistent")

# ─────────────────────────────────────────────────────────────────────────────
# Ping worker
# ─────────────────────────────────────────────────────────────────────────────

def ping_worker(ping_path, stop_event):
    """Periodically write a timestamp to ping_path so callers can detect hangs."""
    while not stop_event.is_set():
        try:
            with open(ping_path, "w") as fh:
                fh.write(now() + "\n")
        except Exception:
            pass
        stop_event.wait(PING_INTERVAL)

# ─────────────────────────────────────────────────────────────────────────────
# Test runner
# ─────────────────────────────────────────────────────────────────────────────

# unittest verbose emits one "test_x (Class) ... ok|FAIL|ERROR|skipped 'reason'"
# line per subtest, sometimes split across lines when a docstring is shown.
SUBTEST_LINE_RE = re.compile(
    r"^(?P<name>test_[A-Za-z0-9_]+)\s+\((?P<cls>[A-Za-z0-9_.]+)\)\s*"
)
SUBTEST_VERDICT_RE = re.compile(
    r"\.{3}\s*(?P<verdict>ok|FAIL|ERROR|skipped(?:\s+'[^']*')?)\s*$"
)
UNITTEST_FINAL_RE = re.compile(
    r"^(?P<status>OK(?:\s*\(.*\))?|FAILED(?:\s*\(.*\))?|ERROR(?:\s*\(.*\))?)\s*$"
)


def parse_subtests(out_path):
    """Walk the unittest output of one test file and return a verdict summary.

    Returns dict:
        ran           int       count of subtests that started
        ok            int
        fail          int
        error         int
        skipped       int
        last_subtest  str|None  most recent subtest name observed (for hangs)
        last_verdict  str|None  ok/FAIL/ERROR/skipped/None
        final_line    str|None  last 'OK'/'FAILED'/'ERROR' summary line, if any
    """
    summary = {
        "ran": 0,
        "ok": 0,
        "fail": 0,
        "error": 0,
        "skipped": 0,
        "last_subtest": None,
        "last_verdict": None,
        "final_line": None,
    }
    pending_name = None
    try:
        with open(out_path, "r") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                m = SUBTEST_LINE_RE.match(line)
                if m:
                    pending_name = m.group("name")
                    summary["ran"] += 1
                    summary["last_subtest"] = pending_name
                    summary["last_verdict"] = None
                v = SUBTEST_VERDICT_RE.search(line)
                if v and pending_name is not None:
                    verdict = v.group("verdict")
                    if verdict == "ok":
                        summary["ok"] += 1
                        summary["last_verdict"] = "ok"
                    elif verdict.startswith("FAIL"):
                        summary["fail"] += 1
                        summary["last_verdict"] = "FAIL"
                    elif verdict.startswith("ERROR"):
                        summary["error"] += 1
                        summary["last_verdict"] = "ERROR"
                    elif verdict.startswith("skipped"):
                        summary["skipped"] += 1
                        summary["last_verdict"] = "skipped"
                    pending_name = None
                f = UNITTEST_FINAL_RE.match(line.strip())
                if f:
                    summary["final_line"] = f.group("status")
    except OSError:
        pass
    return summary


def trim_passing_log(out_path, keep_lines=40):
    """Truncate a clean PASS log to its last keep_lines lines.

    Skip-only output (which is mostly noise for triage) gets compressed to
    the tail of the file plus a count header. The full file is preserved
    on FAIL/ERROR/timeout for diagnostics.
    """
    try:
        with open(out_path, "r") as fh:
            lines = fh.readlines()
        if len(lines) <= keep_lines + 5:
            return
        head = lines[:2]   # START line + the unittest invocation
        tail = lines[-keep_lines:]
        elided = len(lines) - len(head) - len(tail)
        with open(out_path, "w") as fh:
            fh.writelines(head)
            fh.write("[... {} lines elided (passing test, full output suppressed) ...]\n".format(elided))
            fh.writelines(tail)
    except OSError:
        pass


def write_result_line(out_path, module_name, status, duration_s,
                      timeout_killed, parsed):
    """Write a single machine-parseable RESULT key=value line at the end of out_path."""
    fields = [
        "RESULT",
        "name={}".format(module_name),
        "status={}".format(status),
        "duration={:.1f}".format(duration_s),
        "timeout_killed={}".format(1 if timeout_killed else 0),
        "ran={}".format(parsed["ran"]),
        "ok={}".format(parsed["ok"]),
        "fail={}".format(parsed["fail"]),
        "error={}".format(parsed["error"]),
        "skipped={}".format(parsed["skipped"]),
        "last_subtest={}".format(parsed["last_subtest"] or "-"),
        "last_verdict={}".format(parsed["last_verdict"] or "-"),
    ]
    try:
        with open(out_path, "a") as fh:
            fh.write(" ".join(fields) + "\n")
    except OSError:
        pass


def _file_contains_no_tests_marker(path):
    """True if the unittest output for path contains 'NO TESTS RAN'.

    Older Python (≤3.11) prints this line and exits 0; newer Python prints
    it and exits 5. We treat both as PASS-via-empty.
    """
    try:
        with open(path, "r") as fh:
            for line in fh:
                if line.strip().startswith("NO TESTS RAN"):
                    return True
    except OSError:
        pass
    return False


def run_single_test(python_exe, tests_dir, module_name, out_path):
    """Run one test module; return (passed, info_dict) for index/json aggregation.

    info_dict is suitable for rendering an index.txt row and a failed.json entry.
    """
    append_log(out_path, "=== START {} ===".format(module_name))
    t0 = time.time()
    # Tag any aionetiface runtime logs ( log() / log_exception() outputs in
    # ~/aionetiface/logs/ ) with the test module name so they can be
    # correlated back to the test that produced them. Without this, logs
    # are only identifiable by the opaque (pid, tid) suffix.
    rc, _ = run_cmd(
        [python_exe, "-W", "ignore::ResourceWarning", "-m", "unittest", module_name, "-v"],
        cwd=tests_dir,
        log_path=out_path,
        timeout=TEST_TIMEOUT,
        env_extra={"AIONETIFACE_LOG_TAG": module_name},
    )
    duration = time.time() - t0
    timeout_killed = (rc == -1)

    parsed = parse_subtests(out_path)

    # Detect "NO TESTS RAN" -- Python 3.12+ exits with rc=5 when unittest
    # discovers a module with zero test methods. Older Pythons exit with
    # rc=0 in that case. We treat both uniformly as PASS-via-empty so an
    # incomplete or stub-only test file doesn't break the matrix.
    no_tests_ran = (rc == 5) or _file_contains_no_tests_marker(out_path)

    # Status precedence:
    #   TIMEOUT  - the unittest process was SIGKILL'd before a final OK/FAILED line
    #   FAIL     - any subtest failed/errored, OR final line says FAILED/ERROR
    #   PASS     - rc==0 OR (timeout but unittest already printed final OK)
    #              OR no tests discovered (empty / stub-only test file)
    if parsed["final_line"] and parsed["final_line"].startswith("OK"):
        status = "PASS"
    elif parsed["final_line"] and (parsed["final_line"].startswith("FAILED") or parsed["final_line"].startswith("ERROR")):
        status = "FAIL"
    elif timeout_killed:
        status = "TIMEOUT"
    elif no_tests_ran:
        status = "PASS"
    elif rc == 0:
        status = "PASS"
    else:
        status = "FAIL"

    passed = (status == "PASS")
    end_marker = {
        "PASS":    "PASSED",
        "FAIL":    "FAILED (rc={})".format(rc),
        "TIMEOUT": "TIMEOUT (last_subtest={})".format(parsed["last_subtest"] or "-"),
    }[status]
    append_log(out_path, "=== END {} : {} ===".format(module_name, end_marker))
    write_result_line(out_path, module_name, status, duration, timeout_killed, parsed)

    # Compress passing logs so cat *.txt stays scannable.
    if passed:
        trim_passing_log(out_path)

    info = {
        "module": module_name,
        "status": status,
        "duration": round(duration, 1),
        "timeout_killed": bool(timeout_killed),
        "ran": parsed["ran"],
        "ok": parsed["ok"],
        "fail": parsed["fail"],
        "error": parsed["error"],
        "skipped": parsed["skipped"],
        "last_subtest": parsed["last_subtest"],
        "last_verdict": parsed["last_verdict"],
    }
    return passed, info


def test_worker(python_exe, tests_dir, work_q, results, lock):
    """Thread worker: pull items from work_q until empty."""
    while True:
        try:
            module_name, out_path = work_q.get_nowait()
        except queue.Empty:
            break
        passed, info = run_single_test(python_exe, tests_dir, module_name, out_path)
        with lock:
            results.append((module_name, passed, info))
        work_q.task_done()

# ─────────────────────────────────────────────────────────────────────────────
# Orphan cleanup
# ─────────────────────────────────────────────────────────────────────────────

def wipe_aionetiface_logs():
    """Clear ~/aionetiface/logs at the start of each run.

    Runtime log files (log() / log_exception()) accumulate per (pid, tid)
    and there's no built-in cleanup. Wiping at startup keeps the dir
    scannable when triaging a specific run's logs.
    """
    logs_dir = os.path.join(os.path.expanduser("~"), "aionetiface", "logs")
    if not os.path.isdir(logs_dir):
        return
    for entry in os.listdir(logs_dir):
        if not entry.startswith("aionetiface_"):
            continue
        path = os.path.join(logs_dir, entry)
        try:
            os.remove(path)
        except OSError:
            pass


def kill_orphan_python_processes():
    """Kill all python.exe processes on Windows except this one."""
    if sys.platform != "win32":
        return
    current_pid = os.getpid()
    try:
        subprocess.call(
            [
                "taskkill", "/f", "/im", "python.exe",
                "/fi", "PID ne {}".format(current_pid),
            ],
            stdout=open(os.devnull, "w"),
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError):
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Run tests for a p2pd-family repo.")
    parser.add_argument("repo",           help="aionetiface | namebump | sidewire | p2pd")
    parser.add_argument("python_version",
                        help="e.g. 3.8.6  or  lowest | middle | highest")
    parser.add_argument("test_name",      help="test module name or 'all'")
    parser.add_argument("--workers", type=int, default=0,
                        help="override worker count (default: cpu_count-2)")
    args = parser.parse_args()

    kill_orphan_python_processes()
    wipe_aionetiface_logs()

    # Resolve version alias before anything else so the resolved value is used
    # in log filenames, find_python(), and all subsequent logging.
    version_spec       = args.python_version
    args.python_version = resolve_python_version(version_spec)

    timestamp = "{}-{}".format(
        datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
        os.getpid(),
    )

    # Resolve python + repo paths.
    python_exe = find_python(args.python_version)
    repo_dir   = find_repo(args.repo)
    if not repo_dir:
        sys.exit("ERROR: cannot find repo '{}' in search paths".format(args.repo))

    repo_dirs = {}
    for name in ALL_REPOS:
        d = find_repo(name)
        if d:
            repo_dirs[name] = d

    tests_dir = os.path.join(repo_dir, "tests")
    if not os.path.isdir(tests_dir):
        sys.exit("ERROR: tests dir not found: {}".format(tests_dir))

    # Per-run log directory: ~/test_out/<repo>/<version_arg>/<timestamp-pid>/
    run_dir   = make_run_dir(args.repo, version_spec, timestamp)
    setup_log = os.path.join(run_dir, "setup.txt")
    ping_path = os.path.join(run_dir, "ping.txt")

    append_log(setup_log, "runner_version : {}".format(VERSION))
    append_log(setup_log, "started_at : {}".format(now()))
    if version_spec != args.python_version:
        append_log(setup_log, "version    : {} -> {}".format(version_spec, args.python_version))
    append_log(setup_log, "python_exe : {}".format(python_exe))
    append_log(setup_log, "repo_dir   : {}".format(repo_dir))
    append_log(setup_log, "repos found: {}".format(sorted(repo_dirs.keys())))
    stop_ping = threading.Event()
    ping_th   = threading.Thread(target=ping_worker, args=(ping_path, stop_ping))
    ping_th.daemon = True
    ping_th.start()

    # Git reset + reinstall all repos.
    setup_repos(python_exe, repo_dirs, setup_log)

    # Record resolved SHAs after the reset/pull so triage knows exactly
    # what code this run is testing without scrolling install output.
    shas = get_repo_shas(repo_dirs)
    sha_str = " ".join("{}={}".format(k, shas[k]) for k in sorted(shas))
    append_log(setup_log, "git_shas: {}".format(sha_str))

    # Discover test modules.
    if args.test_name == "all":
        pattern      = os.path.join(tests_dir, "test_*.py")
        test_modules = sorted(
            os.path.splitext(os.path.basename(f))[0]
            for f in glob.glob(pattern)
        )
        if not test_modules:
            sys.exit("ERROR: no test_*.py files found in {}".format(tests_dir))
    else:
        test_modules = [args.test_name]

    # Build the work queue; keep ordered list of log paths for final report.
    # Pre-create every log file blank so hung tests show up as empty files.
    work_q    = queue.Queue()
    log_paths = []
    for module in test_modules:
        out_path = os.path.join(run_dir, module + ".txt")
        open(out_path, "a").close()
        log_paths.append((module, out_path))
        work_q.put((module, out_path))

    # Determine parallelism.
    if args.workers > 0:
        num_workers = args.workers
    elif args.test_name == "all":
        try:
            ncpu = multiprocessing.cpu_count() or 0
        except Exception:
            ncpu = 0
        # cpu_count of 1 means the value is unreliable (VM exposing fewer
        # vCPUs than the host has).  Tests are I/O-bound so DEFAULT_WORKERS
        # concurrent subprocesses is fine regardless of vCPU count.
        num_workers = max(1, ncpu - 2) if ncpu > 2 else DEFAULT_WORKERS
    else:
        num_workers = 1

    num_workers = min(num_workers, len(test_modules))
    append_log(setup_log, "workers: {} for {} test files".format(num_workers, len(test_modules)))

    # Run tests.
    results = []
    lock    = threading.Lock()
    threads = []
    for _ in range(num_workers):
        t = threading.Thread(
            target=test_worker,
            args=(python_exe, tests_dir, work_q, results, lock),
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    stop_ping.set()

    # Tally.
    total  = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed

    # summary.txt — human-readable per-file verdict list.
    summary_log = os.path.join(run_dir, "summary.txt")
    append_log(summary_log, "DONE: {}/{} passed, {} failed".format(passed, total, failed))
    for module, ok, _info in sorted(results):
        append_log(summary_log, "{}: {}".format(module, "PASS" if ok else "FAIL"))

    # index.txt — one row per test file with status, duration, and the last
    # subtest seen. Lets agents grep for hangs/fails across the whole matrix
    # without opening per-test files.
    index_log = os.path.join(run_dir, "index.txt")
    info_by_module = {info["module"]: info for _, _, info in results}
    with open(index_log, "w") as fh:
        fh.write(
            "# module status duration_s ran ok fail error skipped last_subtest last_verdict\n"
        )
        for module, _ok, _info in sorted(results):
            i = info_by_module[module]
            fh.write(
                "{module} {status} {duration} ran={ran} ok={ok} fail={fail} "
                "error={error} skipped={skipped} last_subtest={last_subtest} "
                "last_verdict={last_verdict}\n".format(
                    module=module,
                    status=i["status"],
                    duration=i["duration"],
                    ran=i["ran"],
                    ok=i["ok"],
                    fail=i["fail"],
                    error=i["error"],
                    skipped=i["skipped"],
                    last_subtest=i["last_subtest"] or "-",
                    last_verdict=i["last_verdict"] or "-",
                )
            )

    msg = "DONE: {}/{} passed, {} failed  [pid={}]".format(
        passed, total, failed, os.getpid()
    )
    print(msg)
    append_log(setup_log, msg)

    # failed.json — structured failure list keyed by test-file, anchored on
    # parser-derived status so it ignores stray "fail" substrings in skip
    # messages. Includes timeout vs fail distinction and the last subtest
    # observed (the one that hung, on TIMEOUT).
    failed_log_json = os.path.join(run_dir, "failed.json")
    failures = {
        info["module"]: {
            "status": info["status"],
            "duration": info["duration"],
            "timeout_killed": info["timeout_killed"],
            "ran": info["ran"],
            "ok": info["ok"],
            "fail": info["fail"],
            "error": info["error"],
            "skipped": info["skipped"],
            "last_subtest": info["last_subtest"],
            "last_verdict": info["last_verdict"],
        }
        for _module, ok, info in results
        if not ok
    }
    try:
        with open(failed_log_json, "w") as fh:
            json.dump(failures, fh, indent=2, sort_keys=True)
    except OSError:
        pass

    # failed.txt — human-readable companion: one block per failing test file
    # with the captured RESULT line plus the FAIL/ERROR markers from the
    # unittest output. Anchored on the parser, so skipped tests no longer
    # show up just because their skip message contained the word "fail".
    failed_log = os.path.join(run_dir, "failed.txt")
    with open(failed_log, "w") as out_fh:
        for module, ok, info in sorted(results):
            if ok:
                continue
            out_fh.write(
                "=== {module} :: {status} (last_subtest={last}) ===\n".format(
                    module=module,
                    status=info["status"],
                    last=info["last_subtest"] or "-",
                )
            )
            path = os.path.join(run_dir, module + ".txt")
            try:
                with open(path, "r") as fh:
                    for line in fh:
                        if line.startswith("RESULT "):
                            out_fh.write(line)
                            continue
                        # Anchor on unittest's actual marker lines, not on
                        # any string containing "fail".
                        stripped = line.lstrip()
                        if (
                            stripped.startswith("FAIL:")
                            or stripped.startswith("ERROR:")
                            or stripped.startswith("FAILED")
                            or stripped.startswith("AssertionError")
                            or "[TIMED OUT" in stripped
                        ):
                            out_fh.write(line if line.endswith("\n") else line + "\n")
            except OSError:
                pass
            out_fh.write("\n")

    # Print all log file paths so callers can read them directly.
    print("LOG_FILES_BEGIN")
    print("setup: {}".format(setup_log))
    print("summary: {}".format(summary_log))
    print("index: {}".format(index_log))
    print("failed: {}".format(failed_log))
    print("failed_json: {}".format(failed_log_json))
    for module, path in log_paths:
        print("{}: {}".format(module, path))
    print("LOG_FILES_END")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
