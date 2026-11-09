# Centinela Code Scanner

Recursive vulnerability scanner for source code, powered by the **Centinela** family of small security models (0.5B and 1.5B, Q4_K_M GGUF). Runs entirely on CPU via `llama-server` from llama.cpp — no cloud, no GPU, no API keys.

Given a directory, it walks every code file recursively, chunks each file, asks the model to classify every chunk against a fixed vocabulary of 46 vulnerability types, and ranks the files by how confident the model is that they are vulnerable.

## Features

- **Three modes**: `fast` (0.5B), `precise` (1.5B), `fast+precise` (0.5B screens everything, 1.5B re-checks only the hits).
- **Automatic server lifecycle**: spawns `llama-server` on a free port, waits for `/health`, scans, kills it. Never leaves orphan processes.
- **Automatic model download**: if the GGUF files are missing, prompts and downloads them into `./centinela-scanner-models/`.
- **Ranked output**: files are sorted by the geometric mean of the per-token probabilities of the predicted vulnerability label — the most likely hits come first.
- **JSON output**: `--json results.json` for integration with other tools.
- **Zero Node dependencies**: CLI parsing goes through the bash version of [SimpleArgumentsParser](https://github.com/stringmanolo/simpleargumentsparser).

## Requirements

- `bash`
- `python3` (3.10+)
- `git` (for vendoring the CLI parser)
- `llama-server` in `PATH` (from [llama.cpp](https://github.com/ggerganov/llama.cpp))
- ~1.7 GB of free disk space for both GGUF models

Add this section to `README.md`, right after `## Requirements` and before `## Installation` (it explains how to satisfy the `llama-server` requirement on ARM64 Termux):

## Installing llama.cpp in Termux

`centinela_scan.py` requires `llama-server` in `PATH`. On x86_64 desktops this comes from [llama.cpp](https://github.com/ggerganov/llama.cpp) built from source. On ARM64 Android, the easiest path is the prebuilt **b12024** binaries from the [StringManolo/llama.cpp release](https://github.com/StringManolo/llama.cpp/releases/tag/b12024-aarch64), which has two tarballs covering the two Termux environments:

- **Termux (no proot)** — native Termux, ARM64 Android 8+
- **Termux Debian (proot-distro)** — Debian userspace running through `proot-distro` on top of Termux

The release also works on x86_64? No — **aarch64 only**. For x86_64, build llama.cpp from source (see Notes).

### Termux (no proot)

```bash
cd ~
curl -L -O https://github.com/StringManolo/llama.cpp/releases/download/b12024-aarch64/termux-llama.tar.gz
tar -xzvf termux-llama.tar.gz
bash RUN_THIS_TO_INSTALL_LLAMA_IN_TERMUX.sh
```

The install script places the binaries in `$PREFIX/bin` (`/data/data/com.termux/files/usr/bin`) and the shared libraries in `$PREFIX/lib`, both of which are already in `PATH` / `LD_LIBRARY_PATH` in a fresh Termux. Verify:

```bash
which llama-server
llama-server --version
```

Expected output: `/data/data/com.termux/files/usr/bin/llama-server` followed by `version: b12024`.

If `curl` is not installed, `pkg install curl` first.

### Termux Debian (proot-distro)

Enter the proot-distro first, then run everything inside Debian:

```bash
proot-distro login debian
```

```bash
cd ~
curl -L -O https://github.com/StringManolo/llama.cpp/releases/download/b12024-aarch64/llama.cpp-b12024-aarch64-linux.tar.gz
tar -xzvf llama.cpp-b12024-aarch64-linux.tar.gz
```

You can run the binaries directly from the extracted folder:

```bash
cd llama-release
LD_LIBRARY_PATH=. ./llama-server -m model.gguf --port 8080
```

Or install them system-wide so `llama-server` is in `PATH` like any other binary:

```bash
cd ~/llama-release
mkdir -p /usr/local/lib/llama.cpp /usr/local/bin
cp lib*.so* /usr/local/lib/llama.cpp/
cp llama-* /usr/local/bin/
chmod +x /usr/local/bin/llama-*
echo "/usr/local/lib/llama.cpp" > /etc/ld.so.conf.d/llama.cpp.conf
ldconfig
```

`/usr/local/bin` is already in `PATH` on a standard Debian, and `ldconfig` registers the shared libraries so you don't need `LD_LIBRARY_PATH` on every invocation. Verify:

```bash
which llama-server
llama-server --version
```

Expected: `/usr/local/bin/llama-server` and `version: b12024`.

Once confirmed, clean up the tarball and extracted folder:

```bash
cd ~ && rm -rf llama-release llama.cpp-b12024-aarch64-linux.tar.gz
```

If `curl` is missing inside the proot, `apt install curl`.

### Per-user install (no root, no `$PREFIX` pollution)

If you prefer to keep the binaries out of system directories (useful for multiple versions), drop them in `~/bin` and add it to `PATH`:

```bash
mkdir -p ~/bin
cp llama-* lib*.so* ~/bin/
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH="$HOME/bin:$LD_LIBRARY_PATH"' >> ~/.bashrc
source ~/.bashrc
```

This works in both Termux and proot Debian.

### Notes

- The binaries are **dynamically linked** against the `lib*.so*` shipped in the tarball. If you skip the `cp lib*.so*` step (or the `LD_LIBRARY_PATH=.` prefix when running in-place), `llama-server` will fail with:
  ```
  error while loading shared libraries: libllama.so: cannot open shared object file: No such file or directory
  ```
- The prebuilt binaries are **aarch64 only**. On x86_64 (desktop, some Chromebooks, x86 proot images), build from source instead:
  ```bash
  git clone https://github.com/ggerganov/llama.cpp
  cd llama.cpp
  cmake -B build -DLLAMA_CURL=ON
  cmake --build build --config Release -j$(nproc)
  cp build/bin/llama-* ~/bin/   # or /usr/local/bin/
  ```
- `llama-server --version` reports the build number (`b12024`). If you see a different number, you are running a different installation — check `which llama-server` and `echo $PATH`.
- The full list of binaries in the release: `llama-server`, `llama-cli`, `llama-bench`, `llama-quantize`, `llama-gguf-split`, `llama-tokenize`, `llama-embedding`, `llama-perplexity`. All are installed by the steps above.
- The tarball also contains a `README.txt` with the upstream instructions; it is identical in content to this section, so you can ignore it.
```

## Installation

```bash
git clone https://github.com/StringManolo/centinela-code-scanner.git
cd centinela-code-scanner

# Vendor the CLI parser
git clone --depth 1 https://github.com/stringmanolo/simpleargumentsparser.git vendor/simpleargumentsparser

# Python dependency
pip install -r requirements.txt
```

On first run, if the models are not present, the scanner prompts to download them:

```
Model for 'fast' not found. Download from GitHub? [y/N] y
downloading https://github.com/...
  100.0% (466 / 466 MiB)
saved to ./centinela-scanner-models/fast.gguf
```

## Usage

```
python3 centinela_scan.py --path <directory> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `--path`, `-p` | **(required)** Directory to scan recursively |
| `--mode` | `fast` (default), `precise`, or `fast+precise` |
| `--server-fast` | External URL for the 0.5B server (skips spawning) |
| `--server-precise` | External URL for the 1.5B server (skips spawning) |
| `--model-fast` | Path to the 0.5B GGUF (skips download prompt) |
| `--model-precise` | Path to the 1.5B GGUF (skips download prompt) |
| `--json` | Write results to a JSON file instead of stdout |
| `--no-download` | Fail instead of prompting if models are missing |

**Combining `--server-fast` and `--server-precise`** automatically activates `fast+precise` mode. Passing only one forces the corresponding single-model mode.

## Modes

### `fast` — 0.5B only

Fastest scan. Best for quick triage of large codebases on low-power hardware. Misses memory bugs and other C/C++ patterns (the 0.5B was not trained on them).

```bash
python3 centinela_scan.py --path ./my-project
```

### `precise` — 1.5B only

Slower, but detects memory bugs and other nuanced patterns. Still fast enough for targeted audits.

```bash
python3 centinela_scan.py --path ./my-project --mode precise
```

### `fast+precise` — two-stage filter

Phase 1 runs the 0.5B on every file to filter out the obvious SAFE ones. Phase 2 runs the 1.5B only on the files that phase 1 flagged. This is the best trade-off between speed and recall for large projects.

```bash
python3 centinela_scan.py --path ./my-project --mode fast+precise
```

Each phase spawns and tears down its own `llama-server`. The two models never run at the same time — no memory pressure from having both GGUF files loaded simultaneously.

## Examples

### Basic scan, sorted output

```bash
$ python3 centinela_scan.py --path ./src
mode=fast files=42 root=/home/user/project/src
[fast] spawning llama-server on port 41283
server ready at http://127.0.0.1:41283 (14s)
[1/42] /home/user/project/src/auth.js -> SQLI (0.812)
[2/42] /home/user/project/src/utils.js -> SAFE
[3/42] /home/user/project/src/render.js -> XSS (0.934)
...
[42/42] /home/user/project/src/index.js -> SAFE
[fast] shutting down server
0.9340	XSS	/home/user/project/src/render.js
0.8120	SQLI	/home/user/project/src/auth.js
```

### Two-stage scan with JSON output

```bash
python3 centinela_scan.py --path ./src --mode fast+precise --json results.json
```

`results.json`:

```json
[
  {"path": "/home/user/project/src/render.js", "confidence": 0.9340, "label": "XSS"},
  {"path": "/home/user/project/src/auth.js", "confidence": 0.8120, "label": "SQLI"}
]
```

### External servers (two `llama-server` instances on different ports)

```bash
# Terminal 1
llama-server -m ./centinela-scanner-models/fast.gguf --port 8192

# Terminal 2
llama-server -m ./centinela-scanner-models/precise.gguf --port 8193

# Scanner connects to both
python3 centinela_scan.py --path ./src \
  --server-fast http://127.0.0.1:8192 \
  --server-precise http://127.0.0.1:8193
```

The scanner will use the external servers instead of spawning its own. Both must be reachable at startup.

### CI / scripted use

```bash
python3 centinela_scan.py \
  --path ./src \
  --mode precise \
  --model-fast /opt/models/centinela-0.5b.gguf \
  --model-precise /opt/models/centinela-1.5b.gguf \
  --no-download \
  --json report.json
```

## How the confidence score works

For each chunk, the scanner asks the model to emit one label. Then it takes the **per-token log-probabilities** of the emitted label and computes the **geometric mean** — equivalently, `exp(mean(logprob))`.

This is a length-normalized joint probability:

- A single-token label like `XSS` scores by the probability of that one token.
- A multi-token label like `CODE_INJECTION` scores by the geometric mean of its token probabilities, so it is not artificially penalized for being longer.

`SAFE` chunks return confidence `0.0` and are dropped from the output. For files with multiple chunks, the file's reported confidence is the **maximum** confidence across its non-SAFE chunks — so a single high-confidence hit is enough to surface a file.

## File type coverage

The scanner classifies files with these extensions:

```
JavaScript/TypeScript:  .js .mjs .cjs .ts .tsx .jsx
Python:                 .py
Ruby/PHP/Java/Kotlin:   .rb .php .java .kt .kts
C/C++/C#:               .c .h .cpp .cc .cxx .hpp .hh .cs
Go/Rust/Swift/Scala:    .go .rs .swift .scala
Shell:                  .sh .bash .zsh
Config/Data:            .sql .html .htm .vue .svelte
Perl:                   .pl
```

Other files (binaries, Markdown, JSON, YAML, etc.) are skipped. If you want to add extensions, edit `CODE_EXTS` in `centinela_scan.py`.

## Chunking

Files larger than 1200 characters are split into overlapping chunks (150-character overlap). This:

- Keeps every request within the 2048-token context of the model.
- Prevents missing a vulnerability that falls exactly at a chunk boundary.

A vulnerability anywhere in a file contributes to the file's score; the file is reported once at its strongest signal.

## Models

The scanner downloads the **Q4_K_M** quantizations by default, which offer the best size/quality trade-off for CPU inference:

| Model | Size | Trained for | Detectable classes |
|---|---|---|---|
| `fast.gguf` | ~466 MB | JavaScript, web vulnerabilities | 25 "old" classes |
| `precise.gguf` | ~942 MB | JavaScript + C/C++ | 25 old + 12 memory + 8 "other new" |

Both are from the [Centinela](https://github.com/StringManolo/centinela-0.5b) project. If you want to use a different quantization (F32, F16, Q8_0, Q6_K, Q3_K_M, Q2_K), download it manually and pass it via `--model-fast` / `--model-precise`.

## Limitations

- **The 0.5B model does not detect memory bugs.** It was trained on JavaScript vulnerability classes only. For C/C++, use `precise` or `fast+precise`.
- **Chunk-level scanning, not semantic analysis.** Each chunk is classified independently. Cross-function dataflow or inter-file taint is not modelled.
- **Designed for triage, not alerts.** Use the output to prioritize files for human review. It is not an automated alerting system.
- **CPU inference is slow.** Expect 2–5 seconds per chunk on modern hardware, longer on low-power devices (P40 Lite-class phones: ~5–10 s/chunk).

## Troubleshooting

**`llama-server` not found**

```
error: FileNotFoundError: [Errno 2] No such file or directory: 'llama-server'
```

Install llama.cpp and make sure `llama-server` is in `PATH`:

```bash
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp && cmake -B build && cmake --build build --config Release
export PATH="$PWD/build/bin:$PATH"
```

**Server fails to start within 180 seconds**

Increase `SERVER_START_TIMEOUT` in `centinela_scan.py`. On very slow hardware (P40 Lite), loading the 1.5B model can take 90+ seconds.

**Parser not found**

```
error: parser not found at .../vendor/simpleargumentsparser/other_languages/bash/parseCLI
```

Run the vendoring step from the installation instructions.

**Model download hangs**

GitHub releases sometimes rate-limit anonymous downloads. If the progress bar stalls, cancel and re-run — the scanner resumes from where it left off (a partial file is kept on disk and the download restarts from 0, but GitHub's CDN usually picks up the speed again).

## Related

- [Centinela](https://github.com/StringManolo/centinela-0.5b) — training pipeline and GGUF releases for the 0.5B and 1.5B security models
- [llama.cpp](https://github.com/ggerganov/llama.cpp) — the inference engine behind `llama-server`
- [llama.cpp-termux](https://github.com/stringmanolo/llama.cpp) — the inference engine behind `llama-server`
- [SimpleArgumentsParser](https://github.com/stringmanolo/simpleargumentsparser) — bash CLI parser
