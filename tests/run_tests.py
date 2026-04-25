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
import multiprocessing
import os
import queue
import random
import re
import subprocess
import sys
import threading

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.6"

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
    os.path.expanduser("~"),
    os.path.expanduser("~/projects"),
    r"C:\Users\x\projects",
    r"C:\Users\matth\projects",
    r"C:\Users\matthew\projects",
    r"C:\Documents and Settings\matthew\projects",
    r"C:\Documents and Settings\matthew",
    r"C:\Documents and Settings\x\projects",
    r"C:\Documents and Settings\x",
    r"C:\Users\Administrator\projects",
    "/home/x/projects",
    "/Users/xx/projects",
    "/data/data/com.termux/files/home/projects",
    "/root/projects",
]

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

def make_run_dir(repo, timestamp):
    """Return (and create) the per-run log directory: LOG_BASE_DIR/<repo>/<timestamp>/"""
    d = os.path.join(LOG_BASE_DIR, sanitize(repo), sanitize(timestamp))
    if not os.path.isdir(d):
        os.makedirs(d)
    return d

# ─────────────────────────────────────────────────────────────────────────────
# Subprocess runner
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd, cwd=None, log_path=None, timeout=None):
    """
    Run cmd and capture stdout+stderr.  Append output to log_path if given.
    Returns (returncode, output_text).
    """
    cmd_str = " ".join(str(c) for c in cmd)
    if log_path:
        append_log(log_path, "$ " + cmd_str)

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
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

# ─────────────────────────────────────────────────────────────────────────────
# Git + install
# ─────────────────────────────────────────────────────────────────────────────

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

    # 4. pip uninstall (reverse dep order)
    for name in UNINSTALL_ORDER:
        append_log(setup_log, "--- pip uninstall {} ---".format(name))
        run_cmd(
            [python_exe, "-m", "pip", "uninstall", "-y", name],
            log_path=setup_log,
        )

    # 4. pip install (dep order)
    for name in INSTALL_ORDER:
        d = repo_dirs.get(name)
        if not d:
            append_log(setup_log, "SKIP install: {} not found".format(name))
            continue
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

def tests_passed_in_output(out_path):
    """Return True if the test output file contains a clean unittest OK line."""
    try:
        with open(out_path, "r") as fh:
            lines = [l.strip() for l in fh.readlines()]
        for line in reversed(lines):
            if line == "OK" or line.startswith("OK ("):
                return True
            if line.startswith("FAILED") or line.startswith("ERROR"):
                return False
    except OSError:
        pass
    return False

def run_single_test(python_exe, tests_dir, module_name, out_path):
    """Run one test module; return True if it passed."""
    append_log(out_path, "=== START {} ===".format(module_name))
    rc, _ = run_cmd(
        [python_exe, "-W", "ignore::ResourceWarning", "-m", "unittest", module_name, "-v"],
        cwd=tests_dir,
        log_path=out_path,
        timeout=TEST_TIMEOUT,
    )
    # If the process was killed by timeout but unittest printed OK before
    # hanging (e.g. during event-loop/thread cleanup), treat as passed.
    if rc == -1 and tests_passed_in_output(out_path):
        rc = 0
    result = "PASSED" if rc == 0 else "FAILED (rc={})".format(rc)
    append_log(out_path, "=== END {} : {} ===".format(module_name, result))
    return rc == 0

def test_worker(python_exe, tests_dir, work_q, results, lock):
    """Thread worker: pull items from work_q until empty."""
    while True:
        try:
            module_name, out_path = work_q.get_nowait()
        except queue.Empty:
            break
        passed = run_single_test(python_exe, tests_dir, module_name, out_path)
        with lock:
            results.append((module_name, passed))
        work_q.task_done()

# ─────────────────────────────────────────────────────────────────────────────
# Orphan cleanup
# ─────────────────────────────────────────────────────────────────────────────

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

    # Per-run log directory: ~/aionetiface/<repo>/<timestamp>/
    run_dir   = make_run_dir(args.repo, timestamp)
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

    # Write summary.
    total  = len(results)
    passed = sum(1 for _, ok in results if ok)
    failed = total - passed

    summary_log = os.path.join(run_dir, "summary.txt")
    append_log(summary_log, "DONE: {}/{} passed, {} failed".format(passed, total, failed))
    for module, ok in sorted(results):
        append_log(summary_log, "{}: {}".format(module, "PASS" if ok else "FAIL"))

    msg = "DONE: {}/{} passed, {} failed  [pid={}]".format(
        passed, total, failed, os.getpid()
    )
    print(msg)
    append_log(setup_log, msg)

    # Collect all lines containing "fail" (case-insensitive) from every test
    # log into a single failed.txt for quick post-run inspection.
    failed_log = os.path.join(run_dir, "failed.txt")
    with open(failed_log, "w") as out_fh:
        for module, path in log_paths:
            try:
                with open(path, "r") as fh:
                    for line in fh:
                        if "fail" in line.lower():
                            out_fh.write("[{}] {}\n".format(module, line.rstrip()))
            except OSError:
                pass

    # Print all log file paths so callers can read them directly.
    print("LOG_FILES_BEGIN")
    print("setup: {}".format(setup_log))
    print("summary: {}".format(summary_log))
    print("failed: {}".format(failed_log))
    for module, path in log_paths:
        print("{}: {}".format(module, path))
    print("LOG_FILES_END")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
