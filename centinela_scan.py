#!/usr/bin/env python3
"""
Centinela Code Scanner — recursive vulnerability scanner for source code.

Modes:
  fast          0.5B only
  precise       1.5B only
  fast+precise  0.5B screens all files; 1.5B re-checks only the hits

Reports (always written to reports/<ts>_<mode>/):
  vulns.txt              confirmed vulnerable files, sorted by confidence desc
  unconfirmed_vulns.txt  flagged by 0.5B but 1.5B didn't confirm (fast+precise only)
  suspicious_safe.txt    SAFEs with low P(SAFE) or a vuln candidate
  all_by_risk.txt        everything, sorted by risk desc
  summary.json           metadata
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
TOP_LOGPROBS = 30

DEFAULT_SUSPICIOUS_CONF = 0.7
DEFAULT_SUSPICIOUS_VULN_PROB = 0.15
# Phase-2 confirmation threshold: 1.5B must be this confident in SAFE to truly
# "clear" a 0.5B hit. Below this, the file stays as an "unconfirmed vuln".
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
    --help, -h                  Show this help and exit

REPORTS:
    Every run writes reports/<YYYYMMDD_HHMMSS>_<mode>/ with:
      vulns.txt              confirmed vulns, sorted by confidence desc
      unconfirmed_vulns.txt  0.5B flagged, 1.5B didn't confirm (fast+precise)
      suspicious_safe.txt    SAFEs with low confidence or a vuln candidate
      all_by_risk.txt        all files, sorted by risk desc
      summary.json           metadata

    risk:
      vuln        -> confidence
      unconfirmed -> max(confidence, 1 - phase2_safe_conf)
      safe        -> 1 - confidence
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
        print(f"error: --min-safe-conf must be a number", file=sys.stderr)
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
PROMPT_TMPL = (
    "Analyze the following code for security vulnerabilities.\n"
    "If it is vulnerable, answer with the vulnerability type; if it is not, answer SAFE.\n"
    "Answer with exactly one of: {labels}.\n\nCode:\n```\n{code}\n```"
)

# ---------------------------------------------------------------------------
# Label normalisation
# ---------------------------------------------------------------------------
def _normalize(s: str) -> str:
    s = (s or "").upper().strip()
    s = s.replace(" ", "_").replace("-", "_")
    s = re.sub(r"[^A-Z0-9_]", "", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s

def extract_label(content: str) -> str:
    norm = _normalize(content)
    if not norm:
        return "SAFE"
    for L in LABELS:
        if norm == L.upper():
            return L
    for L in sorted(LABELS, key=len, reverse=True):
        if norm.startswith(L.upper()):
            return L
    return "SAFE"

def matches_label_start(norm_token: str, label: str) -> bool:
    L = label.upper()
    if not norm_token or not L.startswith(norm_token):
        return False
    if len(norm_token) >= len(L):
        return norm_token == L
    return L[len(norm_token)] == "_"

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
# Server lifecycle (tuned for Huawei P40 Lite / Kirin 810)
# ---------------------------------------------------------------------------
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def spawn_server(model_path: Path, port: int) -> subprocess.Popen:
    """
    Launch llama-server with settings tuned for Huawei P40 Lite.
    Env overrides: CENTINELA_THREADS (3), CENTINELA_THREADS_BATCH (2),
                   CENTINELA_CTX (4096)
    """
    threads = int(os.environ.get("CENTINELA_THREADS", "3"))
    threads_batch = int(os.environ.get("CENTINELA_THREADS_BATCH", "2"))
    ctx = int(os.environ.get("CENTINELA_CTX", "4096"))

    cmd = [
        "llama-server",
        "-m", str(model_path),
        "--host", "127.0.0.1",
        "--port", str(port),
        # CPU tuning (Kirin 810: 2× A76 + 6× A55; 3 threads ~= 7.5 t/s, 8 is worse)
        "--threads", str(threads),
        "--threads-batch", str(threads_batch),
        # Context: our chunks are ~1200 chars, template ~200, so 4096 is plenty
        "-c", str(ctx),
        "-b", "512",
        "-ub", "256",
        "-n", "24",
        # Single slot, quantized KV cache
        "--parallel", "1",
        "--cache-ram", "256",
        "--cache-type-k", "q8_0",
        "--cache-type-v", "f16",
        # No prompt shifting, no vision, no remote calls
        "--no-context-shift",
        "--no-mmproj",
        "--no-webui",
        "--offline",
        "--log-colors", "off",
        # Greedy sampling (classification is argmax, not creative generation)
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
# Classification
# ---------------------------------------------------------------------------
def classify_chunk(server: str, code: str) -> dict:
    """
    Returns: {label, confidence, max_vuln_label, max_vuln_prob, empty_output}
      empty_output=True means the model returned nothing usable (suspicious).
    """
    prompt = PROMPT_TMPL.format(labels=", ".join(LABELS), code=code)
    payload = {
        "prompt": prompt,
        "temperature": 0.0,
        "n_predict": 24,
        "logprobs": True,
        "top_logprobs": TOP_LOGPROBS,
        "n_probs": TOP_LOGPROBS,   # legacy alias, ignored if unsupported
        "stop": ["```"],           # no single-\n stop: avoid empty outputs
    }
    try:
        r = requests.post(f"{server}/completion", json=payload, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"  warning: request failed ({e})", file=sys.stderr)
        return {"label": "SAFE", "confidence": 0.0,
                "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

    data = r.json()
    content = (data.get("content") or "").strip()
    label = extract_label(content)

    completion_probs = data.get("completion_probabilities") or []
    if not completion_probs:
        # Model returned no logprobs: very suspicious, flag it.
        return {"label": label, "confidence": 0.0,
                "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

    # Confidence = geometric mean of per-token probabilities up to the label
    cumulative = ""
    sum_lp = 0.0
    n = 0
    matched = False
    for cp in completion_probs:
        piece = cp.get("content", "")
        if "logprob" in cp:
            lp = float(cp["logprob"])
        elif "prob" in cp:
            lp = math.log(max(float(cp["prob"]), 1e-10))
        else:
            lp = 0.0
        cumulative += piece
        sum_lp += lp
        n += 1
        if _normalize(cumulative) == label.upper():
            matched = True
            break
    confidence = math.exp(sum_lp / max(n, 1)) if n > 0 else 0.0

    # max_vuln: inspect top alternatives at position 0
    max_vuln_label = None
    max_vuln_prob = 0.0
    first = completion_probs[0]
    candidates = (first.get("top_logprobs")
                  or first.get("n_probs")
                  or first.get("top_candidates")
                  or [])
    for cand in candidates:
        ctoken = cand.get("content", "")
        if "prob" in cand:
            cprob = float(cand["prob"])
        elif "logprob" in cand:
            cprob = math.exp(float(cand["logprob"]))
        else:
            continue
        cnorm = _normalize(ctoken)
        for L in LABELS:
            if L == "SAFE":
                continue
            if matches_label_start(cnorm, L) and cprob > max_vuln_prob:
                max_vuln_prob = cprob
                max_vuln_label = L
                break

    return {"label": label, "confidence": confidence,
            "max_vuln_label": max_vuln_label, "max_vuln_prob": max_vuln_prob,
            "empty_output": False}

def scan_file(server: str, path: Path) -> dict:
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return {"role": "safe", "label": "SAFE", "confidence": 0.0,
                "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

    chunk_results = [classify_chunk(server, c) for c in chunks(text)]
    if not chunk_results:
        return {"role": "safe", "label": "SAFE", "confidence": 0.0,
                "max_vuln_label": None, "max_vuln_prob": 0.0, "empty_output": True}

    vuln_chunks = [r for r in chunk_results if r["label"] != "SAFE"]
    safe_chunks = [r for r in chunk_results if r["label"] == "SAFE"]

    if vuln_chunks:
        best = max(vuln_chunks, key=lambda r: r["confidence"])
        return {"role": "vuln", "label": best["label"],
                "confidence": best["confidence"],
                "max_vuln_label": best["max_vuln_label"],
                "max_vuln_prob": best["max_vuln_prob"],
                "empty_output": best.get("empty_output", False)}
    else:
        worst = min(safe_chunks, key=lambda r: r["confidence"])
        return {"role": "safe", "label": "SAFE",
                "confidence": worst["confidence"],
                "max_vuln_label": worst["max_vuln_label"],
                "max_vuln_prob": worst["max_vuln_prob"],
                "empty_output": worst.get("empty_output", False)}

def run_scan(files: list, server: str, phase: str = "fast") -> list:
    results = []
    total = len(files)
    for i, f in enumerate(files, 1):
        result = scan_file(server, f)
        result["phase"] = phase
        results.append((f, result))
        if result["role"] == "vuln":
            print(f"[{i}/{total}] {f} -> {result['label']} ({result['confidence']:.3f})",
                  file=sys.stderr)
        else:
            print(f"[{i}/{total}] {f} -> SAFE ({result['confidence']:.3f})",
                  file=sys.stderr)
    return results

# ---------------------------------------------------------------------------
# Mode execution
# ---------------------------------------------------------------------------
def phase_scan(files, kind, external_url, model_path):
    if external_url:
        print(f"[{kind}] using external server {external_url}", file=sys.stderr)
        return run_scan(files, external_url, phase=kind)

    port = free_port()
    print(f"[{kind}] spawning llama-server on port {port}", file=sys.stderr)
    proc = spawn_server(model_path, port)
    try:
        return run_scan(files, f"http://127.0.0.1:{port}", phase=kind)
    finally:
        print(f"[{kind}] shutting down server", file=sys.stderr)
        kill_server(proc)

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
def _is_suspicious(conf: float, max_vuln_prob: float, threshold_conf: float) -> list:
    reasons = []
    if conf < threshold_conf:
        reasons.append(f"low_safe_conf={conf:.3f}<{threshold_conf:.3f}")
    if max_vuln_prob >= DEFAULT_SUSPICIOUS_VULN_PROB:
        reasons.append(f"vuln_candidate_prob={max_vuln_prob:.3f}")
    return reasons

def write_reports(run_id, mode, args, confirmed_vulns, unconfirmed_vulns,
                  safes, all_results, elapsed, threshold_conf):
    run_dir = REPORTS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # --- vulns.txt (confirmed) ---
    with open(run_dir / "vulns.txt", "w", encoding="utf-8") as f:
        f.write(f"# Centinela Code Scanner — confirmed vulnerable files\n")
        f.write(f"# run: {run_id}  mode: {mode}  root: {args['path']}\n")
        f.write(f"# count: {len(confirmed_vulns)}\n")
        f.write(f"# format: confidence\\tlabel\\tphase\\tpath\n")
        f.write("#" + "-" * 78 + "\n")
        for p, r in confirmed_vulns:
            f.write(f"{r['confidence']:.4f}\t{r['label']}\t{r['phase']}\t{p.resolve()}\n")

    # --- unconfirmed_vulns.txt ---
    with open(run_dir / "unconfirmed_vulns.txt", "w", encoding="utf-8") as f:
        f.write(f"# Centinela Code Scanner — 0.5B flagged, 1.5B didn't confirm\n")
        f.write(f"# count: {len(unconfirmed_vulns)}\n")
        f.write(f"# format: risk\\tfast_conf\\tfast_label\\tprecise_safe_conf\\tpath\n")
        f.write("#" + "-" * 78 + "\n")
        for p, r in unconfirmed_vulns:
            f.write(f"{r['risk']:.4f}\t{r['confidence']:.4f}\t{r['label']}\t"
                    f"{r.get('phase2_safe_conf', 0.0):.4f}\t{p.resolve()}\n")

    # --- suspicious_safe.txt ---
    suspicious = []
    for p, r in safes:
        reasons = _is_suspicious(r["confidence"], r["max_vuln_prob"], threshold_conf)
        if reasons:
            risk = max(1.0 - r["confidence"], r["max_vuln_prob"])
            suspicious.append((risk, p, r, reasons))
    suspicious.sort(key=lambda x: x[0], reverse=True)

    with open(run_dir / "suspicious_safe.txt", "w", encoding="utf-8") as f:
        f.write(f"# Centinela Code Scanner — suspicious SAFE (possible false negatives)\n")
        f.write(f"# criteria: P(SAFE)<{threshold_conf:.2f} OR max_vuln_prob>="
                f"{DEFAULT_SUSPICIOUS_VULN_PROB:.2f}\n")
        f.write(f"# count: {len(suspicious)} / {len(safes)} safes\n")
        f.write(f"# format: risk\\tsafe_conf\\tmax_vuln\\tphase\\tpath\\treasons\n")
        f.write("#" + "-" * 78 + "\n")
        for risk, p, r, reasons in suspicious:
            mv = (f"{r['max_vuln_label']}:{r['max_vuln_prob']:.3f}"
                  if r["max_vuln_label"] else "-")
            f.write(f"{risk:.4f}\t{r['confidence']:.4f}\t{mv}\t{r['phase']}\t"
                    f"{p.resolve()}\t{', '.join(reasons)}\n")

    # --- all_by_risk.txt ---
    combined = []
    for p, r in confirmed_vulns:
        combined.append((r["confidence"], "vuln", r["label"], r["phase"], p))
    for p, r in unconfirmed_vulns:
        combined.append((r["risk"], "unconfirmed", r["label"], r["phase"], p))
    for p, r in safes:
        risk = max(1.0 - r["confidence"], r["max_vuln_prob"])
        combined.append((risk, "safe", "SAFE", r["phase"], p))
    combined.sort(key=lambda x: x[0], reverse=True)

    with open(run_dir / "all_by_risk.txt", "w", encoding="utf-8") as f:
        f.write(f"# Centinela Code Scanner — all files by risk\n")
        f.write(f"# risk: vuln=confidence, unconfirmed=max(conf,1-precise_safe), safe=1-confidence\n")
        f.write(f"# format: risk\\trole\\tlabel\\tphase\\tpath\n")
        f.write("#" + "-" * 78 + "\n")
        for risk, role, label, phase, p in combined:
            f.write(f"{risk:.4f}\t{role}\t{label}\t{phase}\t{p.resolve()}\n")

    # --- summary.json ---
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
        "suspicious_safe_count": len(suspicious),
        "phase2_clear_threshold": PHASE2_CLEAR_THRESHOLD,
        "min_safe_conf": args["min_safe_conf"],
        "suspicious_threshold_conf": threshold_conf,
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
    print(f"mode={mode} files={len(files)} root={root}", file=sys.stderr)
    if args["show_safe"]:
        threshold_note = (f"min-safe-conf={args['min_safe_conf']}"
                         if args["min_safe_conf"] > 0 else f"default {DEFAULT_SUSPICIOUS_CONF}")
        print(f"show_safe: on ({threshold_note})", file=sys.stderr)

    confirmed_vulns = []
    unconfirmed_vulns = []

    if mode in ("fast", "precise"):
        model = ensure_model(mode, args[f"model_{mode}"], args["no_download"])
        raw = phase_scan(files, mode, args[f"server_{mode}"], model)
        confirmed_vulns = [(p, r) for p, r in raw if r["role"] == "vuln"]
        safes = [(p, r) for p, r in raw if r["role"] == "safe"]

    else:  # fast+precise
        model_fast = ensure_model("fast", args["model_fast"], args["no_download"])
        model_precise = ensure_model("precise", args["model_precise"], args["no_download"])

        print("=== phase 1: fast (0.5B) screening ===", file=sys.stderr)
        phase1 = phase_scan(files, "fast", args["server_fast"], model_fast)
        phase1_vulns = [(p, r) for p, r in phase1 if r["role"] == "vuln"]
        phase1_safes = [(p, r) for p, r in phase1 if r["role"] == "safe"]
        print(f"phase 1 hits: {len(phase1_vulns)} / {len(files)}", file=sys.stderr)

        if phase1_vulns:
            print("=== phase 2: precise (1.5B) filtering ===", file=sys.stderr)
            hit_paths = [p for p, _ in phase1_vulns]
            phase2 = phase_scan(hit_paths, "precise", args["server_precise"], model_precise)
            phase2_by_path = {p: r for p, r in phase2}

            cleared = 0
            for p, r0 in phase1_vulns:
                r2 = phase2_by_path.get(p)
                if r2 is None:
                    confirmed_vulns.append((p, r0))
                    continue
                if r2["role"] == "vuln":
                    # 1.5B confirmed as vuln (possibly different label)
                    confirmed_vulns.append((p, r2))
                elif r2["confidence"] >= PHASE2_CLEAR_THRESHOLD:
                    # 1.5B confidently says safe → truly cleared
                    cleared += 1
                    r2_copy = dict(r2)
                    r2_copy["phase"] = "precise"
                    phase1_safes.append((p, r2_copy))
                else:
                    # 1.5B says SAFE but not confident → unconfirmed
                    merged = dict(r0)
                    merged["risk"] = max(r0["confidence"], 1.0 - r2["confidence"])
                    merged["phase2_safe_conf"] = r2["confidence"]
                    merged["phase"] = "fast (unconfirmed)"
                    unconfirmed_vulns.append((p, merged))

            print(f"phase 2 confirmed: {len(confirmed_vulns)} / {len(phase1_vulns)}", file=sys.stderr)
            print(f"phase 2 unconfirmed: {len(unconfirmed_vulns)}", file=sys.stderr)
            print(f"phase 2 cleared: {cleared}", file=sys.stderr)
        else:
            print("no hits from fast phase; skipping precise", file=sys.stderr)
            confirmed_vulns = []

        safes = phase1_safes

    confirmed_vulns.sort(key=lambda x: x[1]["confidence"], reverse=True)
    unconfirmed_vulns.sort(key=lambda x: x[1]["risk"], reverse=True)
    safes.sort(key=lambda x: x[1]["confidence"])  # ascending = most suspicious first

    all_results = confirmed_vulns + unconfirmed_vulns + safes
    threshold_conf = (args["min_safe_conf"] if args["min_safe_conf"] > 0
                      else DEFAULT_SUSPICIOUS_CONF)

    elapsed = time.time() - t_start
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{mode}"
    run_dir = write_reports(run_id, mode, args, confirmed_vulns, unconfirmed_vulns,
                            safes, all_results, elapsed, threshold_conf)
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
            else:
                risk = item["risk"]
                hint = ""
                if item.get("max_vuln_label"):
                    hint = f"\t({item['max_vuln_label']}:{item['max_vuln_prob']:.3f})"
                marker = "\tSUSPICIOUS" if item.get("suspicious") else ""
                print(f"{risk:.4f}\tSAFE\t{item['path']}{marker}{hint}")

    # ---- summary at end ----
    print(f"\n=== Scan complete ===", file=sys.stderr)
    print(f"mode: {mode}", file=sys.stderr)
    print(f"total files: {len(all_results)}", file=sys.stderr)
    print(f"confirmed vulns: {len(confirmed_vulns)}", file=sys.stderr)
    print(f"unconfirmed vulns: {len(unconfirmed_vulns)}", file=sys.stderr)
    print(f"safes: {len(safes)}", file=sys.stderr)
    print(f"elapsed: {elapsed/60:.1f} min", file=sys.stderr)

if __name__ == "__main__":
    main()