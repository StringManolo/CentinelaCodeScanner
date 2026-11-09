#!/usr/bin/env python3
"""
Centinela Code Scanner — recursive vulnerability scanner for source code.

Modes:
  fast          0.5B only
  precise       1.5B only
  fast+precise  0.5B screens all files; 1.5B re-checks only the hits

Key design:
  * Uses /v1/chat/completions with --jinja so llama-server applies the
    model's native chat template (exact match with training). This is the
    ONLY path that works reliably: /completion with manual ChatML produces
    "The code snippet is..." instead of the label.
  * Classification is argmax over the log-probs of the first token of each
    label, scanning the first few completion positions. Falls back to
    geometric-mean of the emitted label's per-token probs.
  * UNKNOWN when the model returns no usable signal (not SAFE).
"""

import json
import math
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LABELS_PATH = Path(__file__).parent / "labels.json"
MODEL_DIR = Path(__file__).parent / "centinela-scanner-models"
REPORTS_DIR = Path(__file__).parent / "reports"
CHUNK_SIZE = 1200
CHUNK_OVERLAP = 150
REQUEST_TIMEOUT = 180
SERVER_START_TIMEOUT = 180
SERVER_SHUTDOWN_TIMEOUT = 10
TOP_LOGPROBS = 20
MAX_SCAN_POSITIONS = 5

DEFAULT_SUSPICIOUS_CONF = 0.7
DEFAULT_SUSPICIOUS_VULN_PROB = 0.15
PHASE2_CLEAR_THRESHOLD = 0.5

CODE_EXTS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".py", ".rb", ".php", ".java", ".kt", ".kts",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh",
    ".cs", ".go", ".rs", ".swift", ".scala", ".pl", ".sh",
    ".bash", ".zsh", ".sql", ".html", ".htm", ".vue", ".svelte",
}

MODEL_URLS = {
    "fast": (
        "https://github.com/StringManolo/centinela-0.5b/releases/download/"
        "centinela-2026-11-08-42500936763-0.5B-rslora%2Brank32/"
        "centinela-2026-11-08-42500936763-0.5B-rslora+rank32-Q4_K_M.gguf"
    ),
    "precise": (
        "https://github.com/StringManolo/centinela-0.5b/releases/download/"
        "centinela-2026-11-09-42598667777-1.5B-rslora%2Brank32-qwen25/"
        "centinela-2026-11-09-42598667777-1.5B-rslora+rank32-qwen25-Q4_K_M.gguf"
    ),
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
HELP_TEXT = """\
Centinela Code Scanner — recursive vulnerability scanner for source code.

USAGE:
    python centinela_scan.py --path <directory> [options]

REQUIRED:
    --path, -p <dir>            Directory to scan recursively

MODES:
    --mode <mode>               fast (default) | precise | fast+precise

MODEL / SERVER:
    --server-fast <url>         External 0.5B server URL (skips spawn)
    --server-precise <url>      External 1.5B server URL (skips spawn)
    --model-fast <path>         Path to 0.5B GGUF (skips download prompt)
    --model-precise <path>      Path to 1.5B GGUF (skips download prompt)
    --no-download               Fail if models are missing instead of prompting

OUTPUT:
    --json <file>               Write results as JSON
    --show-safe                 Also list SAFE files (sorted by risk desc)
    --min-safe-conf <float>     Threshold for marking SAFEs SUSPICIOUS (default 0.7)
    --debug                     Dump per-chunk raw output + top logprobs to stderr
    --help, -h                  Show this help and exit

ENDPOINT:
    Primary: /v1/chat/completions with --jinja (native chat template = training).
    Fallback: /completion with manual ChatML if the chat endpoint fails.
"""

def print_help():
    print(HELP_TEXT, end="")

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
def parse_args():
    wrapper = Path(__file__).parent / "parse_cli_json.sh"
    if not wrapper.is_file():
        print(f"error: parser wrapper not found: {wrapper}", file=sys.stderr)
        sys.exit(2)

    result = subprocess.run(
        ["bash", str(wrapper)] + sys.argv[1:],
        capture_output=True, text=True, check=True,
    )
    parsed = json.loads(result.stdout)
    c = parsed.get("c", {}) or {}
    s = parsed.get("s", {}) or {}

    def get(long_name, short_name=None):
        if long_name in c:
            return c[long_name]
        if short_name and short_name in s:
            return s[short_name]
        return None

    def as_bool(val):
        if val is None:
            return False
        if isinstance(val, bool):
            return val
        return str(val).lower() in ("true", "1", "yes")

    path = get("path", "p") or ""
    if not path:
        print("error: --path / -p <directory> is required", file=sys.stderr)
        sys.exit(2)

    server_fast = get("server-fast") or None
    server_precise = get("server-precise") or None

    if server_fast and server_precise:
        mode = "fast+precise"
    else:
        mode = get("mode") or "fast"
        if mode not in ("fast", "precise", "fast+precise"):
            print(f"error: invalid --mode {mode!r}", file=sys.stderr)
            sys.exit(2)
        if server_fast and mode == "precise":
            print("error: --server-fast given but mode=precise", file=sys.stderr)
            sys.exit(2)
        if server_precise and mode == "fast":
            print("error: --server-precise given but mode=fast", file=sys.stderr)
            sys.exit(2)

    min_safe_conf_raw = get("min-safe-conf")
    try:
        min_safe_conf = float(min_safe_conf_raw) if min_safe_conf_raw else 0.0
    except (ValueError, TypeError):
        print("error: --min-safe-conf must be a number", file=sys.stderr)
        sys.exit(2)

    return {
        "path": Path(path).expanduser().resolve(),
        "mode": mode,
        "server_fast": server_fast,
        "server_precise": server_precise,
        "model_fast": get("model-fast") or None,
        "model_precise": get("model-precise") or None,
        "json_out": get("json") or None,
        "no_download": as_bool(get("no-download")),
        "show_safe": as_bool(get("show-safe")),
        "min_safe_conf": min_safe_conf,
        "debug": as_bool(get("debug")),
    }

# ---------------------------------------------------------------------------
# Labels & prompt
# ---------------------------------------------------------------------------
def load_labels():
    with open(LABELS_PATH, encoding="utf-8") as f:
        data = json.load(f)
    labels = data["labels"] if isinstance(data, dict) else data
    if "SAFE" not in labels:
        labels.append("SAFE")
    return labels

LABELS = load_labels()
LABELS_SET = set(LABELS)

INNER_PROMPT = (
    "Analyze the following JavaScript code for security vulnerabilities.\n"
    "If it is vulnerable, answer with the vulnerability type; if it is not, answer SAFE.\n"
    "Answer with exactly one of: {labels}.\n\nCode:\n```javascript\n{code}\n```"
)

def build_user_message(code: str) -> str:
    return INNER_PROMPT.format(labels=", ".join(LABELS), code=code)

# Manual ChatML fallback (only used if /v1/chat/completions fails)
CHATML_PREFIX = "<|im_start|>system\nYou are a helpful assistant.<|im_end|>\n<|im_start|>user\n"
CHATML_SUFFIX = "<|im_end|>\n<|im_start|>assistant\n"

def build_raw_prompt(code: str) -> str:
    return CHATML_PREFIX + build_user_message(code) + CHATML_SUFFIX

# ---------------------------------------------------------------------------
# Label normalisation and first-token map
# ---------------------------------------------------------------------------
def _normalize(s: str) -> str:
    s = (s or "").upper().strip()
    s = s.replace(" ", "_").replace("-", "_")
    s = re.sub(r"[^A-Z0-9_]", "", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s

def extract_label_from_text(content: str) -> Optional[str]:
    norm = _normalize(content)
    if not norm:
        return None
    if norm in LABELS_SET:
        return norm
    for L in sorted(LABELS, key=len, reverse=True):
        if norm.startswith(L.upper()):
            return L
    return None

def build_first_token_map() -> dict:
    """Map 'possible first token' -> [labels whose text starts that way]."""
    m = {}
    for L in LABELS:
        m.setdefault(L, []).append(L)
        parts = L.split("_")
        for i in range(1, len(parts)):
            prefix = "_".join(parts[:i])
            if prefix not in m:
                m[prefix] = []
            if L not in m[prefix]:
                m[prefix].append(L)
    return m

FIRST_TOKEN_MAP = build_first_token_map()

# ---------------------------------------------------------------------------
# File discovery & chunking
# ---------------------------------------------------------------------------
def iter_code_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in CODE_EXTS:
            yield p

def chunks(text: str):
    if len(text) <= CHUNK_SIZE:
        yield text
        return
    start = 0
    while start < len(text):
        end = min(start + CHUNK_SIZE, len(text))
        yield text[start:end]
        if end == len(text):
            break
        start = end - CHUNK_OVERLAP

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def spawn_server(model_path: Path, port: int) -> subprocess.Popen:
    """
    Launch llama-server with --jinja so /v1/chat/completions uses the
    GGUF's native chat_template (matches training).

    Env overrides:
      CENTINELA_THREADS         default 3 (2×A76 + 1×A55 for Kirin 810)
      CENTINELA_THREADS_BATCH   default 2 (prefill: 3 saturated the 1.5B)
      CENTINELA_CTX             default 4096
    """
    threads = int(os.environ.get("CENTINELA_THREADS", "3"))
    threads_batch = int(os.environ.get("CENTINELA_THREADS_BATCH", "2"))
    ctx = int(os.environ.get("CENTINELA_CTX", "4096"))

    cmd = [
        "llama-server",
        "-m", str(model_path),
        "--host", "127.0.0.1",
        "--port", str(port),
        # CPU tuning
        "--threads", str(threads),
        "--threads-batch", str(threads_batch),
        # Context
        "-c", str(ctx),
        "-b", "512",
        "-ub", "256",
        "-n", "64",
        # Single slot, KV cache
        "--parallel", "1",
        "--cache-ram", "512",
        "--cache-type-k", "q8_0",
        "--cache-type-v", "f16",
        # CRITICAL: enables the GGUF's native chat_template
        "--jinja",
        # Behavior
        "--no-context-shift",
        "--no-mmproj",
        "--no-webui",
        "--log-colors", "off",
        # Deterministic sampling
        "--temp", "0.0",
        "--top-k", "1",
        "--top-p", "1.0",
        "--min-p", "0.0",
        "--repeat-penalty", "1.0",
        "--repeat-last-n", "0",
    ]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    t0 = time.time()
    while time.time() - t0 < SERVER_START_TIMEOUT:
        try:
            if requests.get(f"{url}/health", timeout=2).status_code == 200:
                print(f"server ready at {url} ({time.time() - t0:.0f}s)", file=sys.stderr)
                return proc
        except requests.RequestException:
            pass
        if proc.poll() is not None:
            raise RuntimeError(f"llama-server exited early (code {proc.returncode})")
        time.sleep(1)
    proc.terminate()
    proc.wait(timeout=SERVER_SHUTDOWN_TIMEOUT)
    raise RuntimeError(f"server failed to start within {SERVER_START_TIMEOUT}s")

def kill_server(proc: Optional[subprocess.Popen]):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=SERVER_SHUTDOWN_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

# ---------------------------------------------------------------------------
# Model download
# ---------------------------------------------------------------------------
def ensure_model(kind: str, provided: Optional[str], no_download: bool) -> Path:
    if provided:
        p = Path(provided).expanduser()
        if p.is_file():
            return p
        print(f"error: model not found: {p}", file=sys.stderr)
        sys.exit(2)

    MODEL_DIR.mkdir(exist_ok=True)
    target = MODEL_DIR / f"{kind}.gguf"
    if target.exists():
        return target

    if no_download:
        print(f"error: model for {kind!r} not found and --no-download is set", file=sys.stderr)
        sys.exit(2)

    ans = input(f"Model for {kind!r} not found. Download from GitHub? [y/N] ").strip().lower()
    if ans not in ("y", "yes"):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    url = MODEL_URLS[kind]
    print(f"downloading {url}", file=sys.stderr)
    with requests.get(url, stream=True, timeout=600) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        written = 0
        with open(target, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
                written += len(chunk)
                if total:
                    pct = 100 * written / total
                    print(f"\r  {pct:.1f}% ({written >> 20} / {total >> 20} MiB)",
                          end="", file=sys.stderr)
        print(file=sys.stderr)
    print(f"saved to {target}", file=sys.stderr)
    return target

# ---------------------------------------------------------------------------
# Logprob helpers (works with both /v1/chat/completions and /completion)
# ---------------------------------------------------------------------------
def _argmax_over_labels(token_logprobs_list, max_positions=MAX_SCAN_POSITIONS):
    """
    Scan the first `max_positions` completion positions. At each, look at
    top_logprobs and pick the highest-prob label.
    """
    best_label = None
    best_prob = 0.0
    for entry in token_logprobs_list[:max_positions]:
        top = entry.get("top_logprobs") or []
        for cand in top:
            token = (cand.get("token") or cand.get("content") or "").strip().upper()
            if token not in FIRST_TOKEN_MAP:
                continue
            if "logprob" in cand:
                prob = math.exp(float(cand["logprob"]))
            elif "prob" in cand:
                prob = float(cand["prob"])
            else:
                continue
            for L in FIRST_TOKEN_MAP[token]:
                if prob > best_prob:
                    best_prob = prob
                    best_label = L
    return best_label, best_prob

def _geometric_mean_of_label(token_logprobs_list, label):
    """Multiply the emitted label's per-token probs (geometric mean)."""
    cumulative = ""
    sum_lp = 0.0
    n = 0
    for entry in token_logprobs_list:
        tok = entry.get("token") or entry.get("content") or ""
        if "logprob" in entry:
            lp = float(entry["logprob"])
        elif "prob" in entry:
            lp = math.log(max(float(entry["prob"]), 1e-10))
        else:
            lp = 0.0
        cumulative += tok
        sum_lp += lp
        n += 1
        if _normalize(cumulative) == label.upper():
            break
    return math.exp(sum_lp / max(n, 1)) if n > 0 else 0.0

def _max_vuln_from_logprobs(token_logprobs_list):
    """Best non-SAFE candidate across the first few positions."""
    max_label = None
    max_prob = 0.0
    for entry in token_logprobs_list[:3]:
        for cand in entry.get("top_logprobs", []) or []:
            token = (cand.get("token") or cand.get("content") or "").strip().upper()
            if token not in FIRST_TOKEN_MAP:
                continue
            if "logprob" in cand:
                prob = math.exp(float(cand["logprob"]))
            elif "prob" in cand:
                prob = float(cand["prob"])
            else:
                continue
            for L in FIRST_TOKEN_MAP[token]:
                if L == "SAFE":
                    continue
                if prob > max_prob:
                    max_prob = prob
                    max_label = L
    return max_label, max_prob

# ---------------------------------------------------------------------------
# Classification — primary path: /v1/chat/completions with --jinja
# ---------------------------------------------------------------------------
def classify_chunk_chat(server, code, debug=False):
    """Returns None if the chat endpoint is unavailable (caller falls back)."""
    user_msg = build_user_message(code)
    payload = {
        "messages": [{"role": "user", "content": user_msg}],
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": 64,
        "logprobs": True,
        "top_logprobs": TOP_LOGPROBS,
    }
    try:
        r = requests.post(f"{server}/v1/chat/completions",
                          json=payload, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        if debug:
            print(f"  [chat] request failed: {e}", file=sys.stderr)
        return None

    data = r.json()
    try:
        choice = data["choices"][0]
    except (KeyError, IndexError):
        if debug:
            print(f"  [chat] unexpected response: {data}", file=sys.stderr)
        return None

    content = (choice.get("message", {}).get("content") or "").strip()
    token_logprobs = (choice.get("logprobs") or {}).get("content") or []

    if debug:
        print(f"  [chat] raw content: {content!r}", file=sys.stderr)
        if token_logprobs:
            print(f"  [chat] first token: {token_logprobs[0].get('token')!r} "
                  f"logprob={token_logprobs[0].get('logprob')}", file=sys.stderr)
            for cand in (token_logprobs[0].get("top_logprobs") or [])[:5]:
                print(f"    cand: {cand.get('token')!r} "
                      f"logprob={cand.get('logprob')}", file=sys.stderr)

    emitted_label = extract_label_from_text(content)
    emitted_conf = 0.0
    if emitted_label and token_logprobs:
        emitted_conf = _geometric_mean_of_label(token_logprobs, emitted_label)

    argmax_label, argmax_conf = _argmax_over_labels(token_logprobs)

    best_label = None
    best_conf = 0.0
    if emitted_label and emitted_conf >= argmax_conf:
        best_label, best_conf = emitted_label, emitted_conf
    elif argmax_label:
        best_label, best_conf = argmax_label, argmax_conf

    max_vuln_label, max_vuln_prob = _max_vuln_from_logprobs(token_logprobs)

    if best_label is None:
        return {"label": "UNKNOWN", "confidence": 0.0,
                "max_vuln_label": max_vuln_label,
                "max_vuln_prob": max_vuln_prob,
                "empty_output": not bool(content)}
    return {"label": best_label, "confidence": best_conf,
            "max_vuln_label": max_vuln_label,
            "max_vuln_prob": max_vuln_prob, "empty_output": False}

# ---------------------------------------------------------------------------
# Classification — fallback path: /completion with manual ChatML
# ---------------------------------------------------------------------------
def classify_chunk_raw(server, code, debug=False):
    full_prompt = build_raw_prompt(code)
    payload = {
        "prompt": full_prompt,
        "temperature": 0.0,
        "n_predict": 64,
        "logprobs": True,
        "top_logprobs": TOP_LOGPROBS,
        "n_probs": TOP_LOGPROBS,
        "stop": ["<|im_end|>"],
    }
    try:
        r = requests.post(f"{server}/completion", json=payload, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        if debug:
            print(f"  [raw] request failed: {e}", file=sys.stderr)
        return {"label": "UNKNOWN", "confidence": 0.0,
                "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

    data = r.json()
    content = (data.get("content") or "").strip()
    cprobs = data.get("completion_probabilities") or []

    if debug:
        print(f"  [raw] content: {content!r}", file=sys.stderr)
        if cprobs:
            print(f"  [raw] first token: {cprobs[0].get('content')!r} "
                  f"prob={cprobs[0].get('prob')}", file=sys.stderr)

    # Normalise completion_probabilities -> token_logprobs (same shape as chat)
    token_logprobs = []
    for cp in cprobs:
        entry = {
            "token": cp.get("content", ""),
            "logprob": cp.get("logprob",
                              math.log(max(cp.get("prob", 1e-10), 1e-10))),
            "top_logprobs": [
                {"token": c.get("content", ""),
                 "logprob": c.get("logprob",
                                  math.log(max(c.get("prob", 1e-10), 1e-10)))}
                for c in (cp.get("top_logprobs") or cp.get("n_probs") or [])
            ],
        }
        token_logprobs.append(entry)

    emitted_label = extract_label_from_text(content)
    emitted_conf = 0.0
    if emitted_label and token_logprobs:
        emitted_conf = _geometric_mean_of_label(token_logprobs, emitted_label)

    argmax_label, argmax_conf = _argmax_over_labels(token_logprobs)

    best_label = None
    best_conf = 0.0
    if emitted_label and emitted_conf >= argmax_conf:
        best_label, best_conf = emitted_label, emitted_conf
    elif argmax_label:
        best_label, best_conf = argmax_label, argmax_conf

    max_vuln_label, max_vuln_prob = _max_vuln_from_logprobs(token_logprobs)

    if best_label is None:
        return {"label": "UNKNOWN", "confidence": 0.0,
                "max_vuln_label": max_vuln_label,
                "max_vuln_prob": max_vuln_prob,
                "empty_output": not bool(content)}
    return {"label": best_label, "confidence": best_conf,
            "max_vuln_label": max_vuln_label,
            "max_vuln_prob": max_vuln_prob, "empty_output": False}

def classify_chunk(server, code, debug=False):
    """Try chat completions; fall back to raw completion."""
    result = classify_chunk_chat(server, code, debug=debug)
    if result is not None:
        return result
    return classify_chunk_raw(server, code, debug=debug)

# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------
def scan_file(server, path, debug=False):
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return {"role": "unknown", "label": "UNKNOWN", "confidence": 0.0,
                "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

    chunk_results = [classify_chunk(server, c, debug=debug) for c in chunks(text)]
    if not chunk_results:
        return {"role": "unknown", "label": "UNKNOWN", "confidence": 0.0,
                "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

    vuln_chunks = [r for r in chunk_results
                   if r["label"] != "SAFE" and r["label"] != "UNKNOWN"]
    safe_chunks = [r for r in chunk_results if r["label"] == "SAFE"]

    if vuln_chunks:
        best = max(vuln_chunks, key=lambda r: r["confidence"])
        return {"role": "vuln", "label": best["label"],
                "confidence": best["confidence"],
                "max_vuln_label": best["max_vuln_label"],
                "max_vuln_prob": best["max_vuln_prob"],
                "empty_output": best.get("empty_output", False)}

    if safe_chunks:
        worst = min(safe_chunks, key=lambda r: r["confidence"])
        return {"role": "safe", "label": "SAFE",
                "confidence": worst["confidence"],
                "max_vuln_label": worst["max_vuln_label"],
                "max_vuln_prob": worst["max_vuln_prob"],
                "empty_output": worst.get("empty_output", False)}

    return {"role": "unknown", "label": "UNKNOWN", "confidence": 0.0,
            "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

def run_scan(files, server, phase="fast", debug=False):
    results = []
    total = len(files)
    for i, f in enumerate(files, 1):
        t0 = time.time()
        if debug:
            print(f"[{phase}] scanning {f}", file=sys.stderr)
        result = scan_file(server, f, debug=debug)
        elapsed = time.time() - t0
        result["phase"] = phase
        result["elapsed_s"] = round(elapsed, 2)
        results.append((f, result))
        if result["role"] == "vuln":
            print(f"[{i}/{total}] {f} -> {result['label']} "
                  f"({result['confidence']:.3f}) [{elapsed:.1f}s]", file=sys.stderr)
        elif result["role"] == "safe":
            print(f"[{i}/{total}] {f} -> SAFE "
                  f"({result['confidence']:.3f}) [{elapsed:.1f}s]", file=sys.stderr)
        else:
            print(f"[{i}/{total}] {f} -> UNKNOWN [{elapsed:.1f}s]", file=sys.stderr)
    return results

# ---------------------------------------------------------------------------
# Mode execution
# ---------------------------------------------------------------------------
def phase_scan(files, kind, external_url, model_path, debug=False):
    if external_url:
        print(f"[{kind}] using external server {external_url}", file=sys.stderr)
        return run_scan(files, external_url, phase=kind, debug=debug)

    port = free_port()
    print(f"[{kind}] spawning llama-server on port {port}", file=sys.stderr)
    proc = spawn_server(model_path, port)
    try:
        return run_scan(files, f"http://127.0.0.1:{port}", phase=kind, debug=debug)
    finally:
        print(f"[{kind}] shutting down server", file=sys.stderr)
        kill_server(proc)

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
def _is_suspicious(conf, max_vuln_prob, threshold_conf):
    reasons = []
    if conf < threshold_conf:
        reasons.append(f"low_safe_conf={conf:.3f}<{threshold_conf:.3f}")
    if max_vuln_prob >= DEFAULT_SUSPICIOUS_VULN_PROB:
        reasons.append(f"vuln_candidate_prob={max_vuln_prob:.3f}")
    return reasons

def write_reports(run_id, mode, args, confirmed_vulns, unconfirmed_vulns,
                  safes, unknowns, all_results, elapsed, threshold_conf):
    run_dir = REPORTS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    with open(run_dir / "vulns.txt", "w", encoding="utf-8") as f:
        f.write(f"# Centinela Code Scanner — confirmed vulnerable files\n")
        f.write(f"# run: {run_id}  mode: {mode}  root: {args['path']}\n")
        f.write(f"# count: {len(confirmed_vulns)}\n")
        f.write(f"# format: confidence\\tlabel\\tphase\\tpath\n")
        f.write("#" + "-" * 78 + "\n")
        for p, r in confirmed_vulns:
            f.write(f"{r['confidence']:.4f}\t{r['label']}\t{r['phase']}\t{p.resolve()}\n")

    with open(run_dir / "unconfirmed_vulns.txt", "w", encoding="utf-8") as f:
        f.write(f"# Centinela Code Scanner — 0.5B flagged, 1.5B didn't confirm\n")
        f.write(f"# count: {len(unconfirmed_vulns)}\n")
        f.write(f"# format: risk\\tfast_conf\\tfast_label\\tprecise_safe_conf\\tpath\n")
        f.write("#" + "-" * 78 + "\n")
        for p, r in unconfirmed_vulns:
            f.write(f"{r['risk']:.4f}\t{r['confidence']:.4f}\t{r['label']}\t"
                    f"{r.get('phase2_safe_conf', 0.0):.4f}\t{p.resolve()}\n")

    suspicious = []
    for p, r in safes:
        reasons = _is_suspicious(r["confidence"], r["max_vuln_prob"], threshold_conf)
        if reasons:
            risk = max(1.0 - r["confidence"], r["max_vuln_prob"])
            suspicious.append((risk, p, r, reasons))
    suspicious.sort(key=lambda x: x[0], reverse=True)

    with open(run_dir / "suspicious_safe.txt", "w", encoding="utf-8") as f:
        f.write("# Centinela Code Scanner — suspicious SAFE (possible false negatives)\n")
        f.write(f"# criteria: P(SAFE)<{threshold_conf:.2f} OR max_vuln_prob>="
                f"{DEFAULT_SUSPICIOUS_VULN_PROB:.2f}\n")
        f.write(f"# count: {len(suspicious)} / {len(safes)} safes\n")
        f.write("# format: risk\\tsafe_conf\\tmax_vuln\\tphase\\tpath\\treasons\n")
        f.write("#" + "-" * 78 + "\n")
        for risk, p, r, reasons in suspicious:
            mv = (f"{r['max_vuln_label']}:{r['max_vuln_prob']:.3f}"
                  if r["max_vuln_label"] else "-")
            f.write(f"{risk:.4f}\t{r['confidence']:.4f}\t{mv}\t{r['phase']}\t"
                    f"{p.resolve()}\t{', '.join(reasons)}\n")

    combined = []
    for p, r in confirmed_vulns:
        combined.append((r["confidence"], "vuln", r["label"], r["phase"], p))
    for p, r in unconfirmed_vulns:
        combined.append((r["risk"], "unconfirmed", r["label"], r["phase"], p))
    for p, r in safes:
        risk = max(1.0 - r["confidence"], r["max_vuln_prob"])
        combined.append((risk, "safe", "SAFE", r["phase"], p))
    for p, r in unknowns:
        combined.append((0.0, "unknown", "UNKNOWN", r["phase"], p))
    combined.sort(key=lambda x: x[0], reverse=True)

    with open(run_dir / "all_by_risk.txt", "w", encoding="utf-8") as f:
        f.write("# Centinela Code Scanner — all files by risk\n")
        f.write("# risk: vuln=confidence, unconfirmed=max(conf,1-precise_safe), "
                "safe=max(1-conf,max_vuln), unknown=0\n")
        f.write("# format: risk\\trole\\tlabel\\tphase\\tpath\n")
        f.write("#" + "-" * 78 + "\n")
        for risk, role, label, phase, p in combined:
            f.write(f"{risk:.4f}\t{role}\t{label}\t{phase}\t{p.resolve()}\n")

    summary = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "root": str(args["path"]),
        "elapsed_seconds": round(elapsed, 1),
        "total_files": len(all_results),
        "confirmed_vuln_count": len(confirmed_vulns),
        "unconfirmed_vuln_count": len(unconfirmed_vulns),
        "safe_count": len(safes),
        "unknown_count": len(unknowns),
        "suspicious_safe_count": len(suspicious),
        "phase2_clear_threshold": PHASE2_CLEAR_THRESHOLD,
        "classifier": "v1/chat/completions with --jinja (primary) + /completion fallback",
        "chatml_wrapped": True,
    }
    with open(run_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return run_dir

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print_help()
        return

    t_start = time.time()
    args = parse_args()
    root: Path = args["path"]
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    files = list(iter_code_files(root))
    if not files:
        print("no code files found", file=sys.stderr)
        return

    mode = args["mode"]
    debug = args["debug"]
    print(f"mode={mode} files={len(files)} root={root}", file=sys.stderr)
    if debug:
        print("debug: on (raw output and top_logprobs to stderr)", file=sys.stderr)
    if args["show_safe"]:
        print("show_safe: on", file=sys.stderr)

    confirmed_vulns = []
    unconfirmed_vulns = []
    unknowns = []

    if mode in ("fast", "precise"):
        model = ensure_model(mode, args[f"model_{mode}"], args["no_download"])
        raw = phase_scan(files, mode, args[f"server_{mode}"], model, debug=debug)
        confirmed_vulns = [(p, r) for p, r in raw if r["role"] == "vuln"]
        safes = [(p, r) for p, r in raw if r["role"] == "safe"]
        unknowns = [(p, r) for p, r in raw if r["role"] == "unknown"]

    else:  # fast+precise
        model_fast = ensure_model("fast", args["model_fast"], args["no_download"])
        model_precise = ensure_model("precise", args["model_precise"], args["no_download"])

        print("=== phase 1: fast (0.5B) screening ===", file=sys.stderr)
        phase1 = phase_scan(files, "fast", args["server_fast"], model_fast, debug=debug)
        phase1_vulns = [(p, r) for p, r in phase1 if r["role"] == "vuln"]
        phase1_safes = [(p, r) for p, r in phase1 if r["role"] == "safe"]
        phase1_unknowns = [(p, r) for p, r in phase1 if r["role"] == "unknown"]
        print(f"phase 1 hits: {len(phase1_vulns)} / {len(files)}", file=sys.stderr)

        if phase1_vulns:
            print("=== phase 2: precise (1.5B) filtering ===", file=sys.stderr)
            hit_paths = [p for p, _ in phase1_vulns]
            phase2 = phase_scan(hit_paths, "precise", args["server_precise"],
                                model_precise, debug=debug)
            phase2_by_path = {p: r for p, r in phase2}

            cleared = 0
            for p, r0 in phase1_vulns:
                r2 = phase2_by_path.get(p)
                if r2 is None:
                    confirmed_vulns.append((p, r0))
                    continue
                if r2["role"] == "vuln":
                    confirmed_vulns.append((p, r2))
                elif r2["role"] == "unknown":
                    merged = dict(r0)
                    merged["risk"] = r0["confidence"]
                    merged["phase2_safe_conf"] = 0.0
                    merged["phase"] = "fast (unconfirmed-unknown)"
                    unconfirmed_vulns.append((p, merged))
                elif r2["confidence"] >= PHASE2_CLEAR_THRESHOLD:
                    cleared += 1
                    r2_copy = dict(r2)
                    r2_copy["phase"] = "precise"
                    phase1_safes.append((p, r2_copy))
                else:
                    merged = dict(r0)
                    merged["risk"] = max(r0["confidence"], 1.0 - r2["confidence"])
                    merged["phase2_safe_conf"] = r2["confidence"]
                    merged["phase"] = "fast (unconfirmed)"
                    unconfirmed_vulns.append((p, merged))

            print(f"phase 2 confirmed: {len(confirmed_vulns)} / {len(phase1_vulns)}",
                  file=sys.stderr)
            print(f"phase 2 unconfirmed: {len(unconfirmed_vulns)}", file=sys.stderr)
            print(f"phase 2 cleared: {cleared}", file=sys.stderr)
        else:
            print("no hits from fast phase; skipping precise", file=sys.stderr)

        safes = phase1_safes
        unknowns = phase1_unknowns

    confirmed_vulns.sort(key=lambda x: x[1]["confidence"], reverse=True)
    unconfirmed_vulns.sort(key=lambda x: x[1]["risk"], reverse=True)
    safes.sort(key=lambda x: x[1]["confidence"])
    unknowns.sort(key=lambda x: str(x[0]))

    all_results = confirmed_vulns + unconfirmed_vulns + safes + unknowns
    threshold_conf = (args["min_safe_conf"] if args["min_safe_conf"] > 0
                      else DEFAULT_SUSPICIOUS_CONF)

    elapsed = time.time() - t_start
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{mode}"
    run_dir = write_reports(run_id, mode, args, confirmed_vulns, unconfirmed_vulns,
                            safes, unknowns, all_results, elapsed, threshold_conf)
    print(f"reports written to {run_dir}", file=sys.stderr)

    # ---- stdout ----
    out_json = []
    for p, r in confirmed_vulns:
        out_json.append({
            "path": str(p.resolve()), "confidence": round(r["confidence"], 4),
            "label": r["label"], "role": "vuln", "phase": r["phase"],
            "max_vuln_label": r["max_vuln_label"],
            "max_vuln_prob": round(r["max_vuln_prob"], 4) if r["max_vuln_prob"] else 0.0,
        })
    for p, r in unconfirmed_vulns:
        out_json.append({
            "path": str(p.resolve()), "risk": round(r["risk"], 4),
            "confidence": round(r["confidence"], 4),
            "label": r["label"], "role": "unconfirmed", "phase": r["phase"],
            "phase2_safe_conf": round(r.get("phase2_safe_conf", 0.0), 4),
            "max_vuln_label": r["max_vuln_label"],
            "max_vuln_prob": round(r["max_vuln_prob"], 4) if r["max_vuln_prob"] else 0.0,
        })
    if args["show_safe"]:
        for p, r in safes:
            reasons = _is_suspicious(r["confidence"], r["max_vuln_prob"], threshold_conf)
            out_json.append({
                "path": str(p.resolve()), "confidence": round(r["confidence"], 4),
                "risk": round(max(1.0 - r["confidence"], r["max_vuln_prob"]), 4),
                "label": "SAFE", "role": "safe", "phase": r["phase"],
                "suspicious": bool(reasons), "suspicious_reasons": reasons,
                "max_vuln_label": r["max_vuln_label"],
                "max_vuln_prob": round(r["max_vuln_prob"], 4) if r["max_vuln_prob"] else 0.0,
            })
        for p, r in unknowns:
            out_json.append({
                "path": str(p.resolve()), "confidence": 0.0, "risk": 0.0,
                "label": "UNKNOWN", "role": "unknown", "phase": r["phase"],
            })

    if args["json_out"]:
        Path(args["json_out"]).write_text(json.dumps(out_json, indent=2), encoding="utf-8")
        print(f"wrote {args['json_out']}", file=sys.stderr)
    else:
        for item in out_json:
            if item["role"] == "vuln":
                print(f"{item['confidence']:.4f}\t{item['label']}\t{item['path']}")
            elif item["role"] == "unconfirmed":
                print(f"{item['risk']:.4f}\t{item['label']}\t{item['path']}"
                      f"\tUNCONFIRMED (1.5B safe={item['phase2_safe_conf']:.3f})")
            elif item["role"] == "safe":
                hint = (f"\t({item['max_vuln_label']}:{item['max_vuln_prob']:.3f})"
                        if item.get("max_vuln_label") else "")
                marker = "\tSUSPICIOUS" if item.get("suspicious") else ""
                print(f"{item['risk']:.4f}\tSAFE\t{item['path']}{marker}{hint}")
            else:
                print(f"0.0000\tUNKNOWN\t{item['path']}")

    print(f"\n=== Scan complete ===", file=sys.stderr)
    print(f"mode: {mode}", file=sys.stderr)
    print(f"total files: {len(all_results)}", file=sys.stderr)
    print(f"confirmed vulns: {len(confirmed_vulns)}", file=sys.stderr)
    print(f"unconfirmed vulns: {len(unconfirmed_vulns)}", file=sys.stderr)
    print(f"safes: {len(safes)}", file=sys.stderr)
    print(f"unknowns: {len(unknowns)}", file=sys.stderr)
    print(f"elapsed: {elapsed/60:.1f} min", file=sys.stderr)

if __name__ == "__main__":
    main()