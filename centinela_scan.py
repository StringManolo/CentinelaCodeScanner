#!/usr/bin/env python3
"""
Centinela Code Scanner — recursive vulnerability scanner for source code.

Uses a local llama-server (llama.cpp) to classify code chunks against the
Centinela label set. Files are ranked by the model's confidence in the
predicted label.

Modes:
  fast          0.5B only
  precise       1.5B only
  fast+precise  0.5B screens all files; 1.5B re-checks only the hits
"""

import json
import math
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LABELS_PATH = Path(__file__).parent / "labels.json"
MODEL_DIR = Path(__file__).parent / "centinela-scanner-models"
CHUNK_SIZE = 1200
CHUNK_OVERLAP = 150
REQUEST_TIMEOUT = 180
SERVER_START_TIMEOUT = 180
SERVER_SHUTDOWN_TIMEOUT = 10

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
# CLI parsing via SimpleArgumentsParser (bash wrapper)
# ---------------------------------------------------------------------------
def parse_args():
    """
    Call parse_cli_json.sh, which sources SimpleArgumentsParser's bash version,
    runs `parse_cli "$@"`, and dumps the internal state via `cli print`.

    The parser returns:
      {
        "s": { short flags (single dash), e.g. "p": "/path", "v": true },
        "c": { long flags (double dash), e.g. "path": "/path", "verbose": true },
        "o": [ [positional, index], ... ],
        "p": false,
        "e": [],
        "noArgs": bool,
        "argc": int
      }
    """
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

    no_dl = get("no-download")
    if isinstance(no_dl, str):
        no_download = no_dl.lower() in ("true", "1", "yes")
    else:
        no_download = bool(no_dl)

    return {
        "path": Path(path).expanduser().resolve(),
        "mode": mode,
        "server_fast": server_fast,
        "server_precise": server_precise,
        "model_fast": get("model-fast") or None,
        "model_precise": get("model-precise") or None,
        "json_out": get("json") or None,
        "no_download": no_download,
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
    proc = subprocess.Popen(
        [
            "llama-server",
            "-m", str(model_path),
            "--port", str(port),
            "--host", "127.0.0.1",
            "-c", "2048",
            "--no-webui",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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
                    print(f"\r  {pct:.1f}% ({written >> 20} / {total >> 20} MiB)", end="", file=sys.stderr)
        print(file=sys.stderr)
    print(f"saved to {target}", file=sys.stderr)
    return target

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def classify_chunk(server: str, code: str) -> tuple[str, float]:
    """
    Return (label, confidence).

    Confidence = geometric mean of the per-token probabilities of the predicted
    label. Length-normalised so multi-token labels are comparable to single-token
    ones. SAFE -> confidence 0.0 (so safe chunks are filtered out).
    """
    prompt = PROMPT_TMPL.format(labels=", ".join(LABELS), code=code)
    payload = {
        "prompt": prompt,
        "temperature": 0.0,
        "n_predict": 16,
        "logprobs": True,
        "top_logprobs": 3,
        "stop": ["\n", "```", "Code:"],
    }
    try:
        r = requests.post(f"{server}/completion", json=payload, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"  warning: request failed ({e})", file=sys.stderr)
        return "SAFE", 0.0

    data = r.json()
    content = (data.get("content") or "").strip()

    label = None
    for L in sorted(LABELS, key=len, reverse=True):
        if content.upper().startswith(L.upper()):
            label = L
            break

    if label is None or label == "SAFE":
        return "SAFE", 0.0

    completion_probs = data.get("completion_probabilities") or []
    if not completion_probs:
        return label, 0.5

    cumulative = ""
    sum_lp = 0.0
    n = 0
    for cp in completion_probs:
        piece = cp.get("content", "")
        cumulative += piece
        sum_lp += float(cp.get("logprob", 0.0))
        n += 1
        if cumulative.strip().upper() == label:
            break

    confidence = math.exp(sum_lp / max(n, 1))
    return label, confidence

def scan_file(server: str, path: Path) -> tuple[bool, float, str]:
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return False, 0.0, "SAFE"

    best_conf = 0.0
    best_label = "SAFE"
    for chunk in chunks(text):
        label, conf = classify_chunk(server, chunk)
        if label != "SAFE" and conf > best_conf:
            best_conf = conf
            best_label = label
    return best_conf > 0.0, best_conf, best_label

def run_scan(files: list[Path], server: str) -> list[tuple[Path, float, str]]:
    hits = []
    total = len(files)
    for i, f in enumerate(files, 1):
        vuln, conf, label = scan_file(server, f)
        if vuln:
            hits.append((f, conf, label))
        marker = f"{label} ({conf:.3f})" if vuln else "SAFE"
        print(f"[{i}/{total}] {f} -> {marker}", file=sys.stderr)
    return hits

# ---------------------------------------------------------------------------
# Mode execution
# ---------------------------------------------------------------------------
def phase_scan(
    files: list[Path],
    kind: str,
    external_url: Optional[str],
    model_path: Optional[Path],
) -> list[tuple[Path, float, str]]:
    if external_url:
        print(f"[{kind}] using external server {external_url}", file=sys.stderr)
        return run_scan(files, external_url)

    port = free_port()
    print(f"[{kind}] spawning llama-server on port {port}", file=sys.stderr)
    proc = spawn_server(model_path, port)
    try:
        return run_scan(files, f"http://127.0.0.1:{port}")
    finally:
        print(f"[{kind}] shutting down server", file=sys.stderr)
        kill_server(proc)

def main():
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

    if mode == "fast":
        model = ensure_model("fast", args["model_fast"], args["no_download"])
        hits = phase_scan(files, "fast", args["server_fast"], model)

    elif mode == "precise":
        model = ensure_model("precise", args["model_precise"], args["no_download"])
        hits = phase_scan(files, "precise", args["server_precise"], model)

    else:
        model_fast = ensure_model("fast", args["model_fast"], args["no_download"])
        model_precise = ensure_model("precise", args["model_precise"], args["no_download"])

        print("=== phase 1: fast (0.5B) screening ===", file=sys.stderr)
        hits = phase_scan(files, "fast", args["server_fast"], model_fast)
        print(f"phase 1 hits: {len(hits)} / {len(files)}", file=sys.stderr)

        if not hits:
            print("no hits from fast phase; nothing to refine", file=sys.stderr)
        else:
            print("=== phase 2: precise (1.5B) filtering ===", file=sys.stderr)
            hit_paths = [h[0] for h in hits]
            hits = phase_scan(hit_paths, "precise", args["server_precise"], model_precise)

    hits.sort(key=lambda x: x[1], reverse=True)

    out = [
        {"path": str(p.resolve()), "confidence": round(c, 4), "label": lab}
        for p, c, lab in hits
    ]
    if args["json_out"]:
        Path(args["json_out"]).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"wrote {args['json_out']}", file=sys.stderr)
    else:
        for item in out:
            print(f"{item['confidence']:.4f}\t{item['label']}\t{item['path']}")

if __name__ == "__main__":
    main()
