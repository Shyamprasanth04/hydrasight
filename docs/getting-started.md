# Getting Started

## Requirements

- Python **3.10+**
- A [Kali](https://www.kali.org/) backend exposing the `kali-server-mcp` REST API
  (default `http://127.0.0.1:5000`)
- [Ollama](https://ollama.com/) serving a supported model (default
  `qcwind/qwen3-8b-instruct-Q4-K-M:latest` on `http://127.0.0.1:11434`)

## Installation

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,docs]"
```

Or build the distributable artifacts:

```bash
python -m build
pip install dist/hydrasight-*.whl
```

## Docker

```bash
docker compose up --build
```

The image runs as a non-root user (`hydra`, uid 1000) and ships **no offensive
tooling** — commands execute against the separate Kali bridge service. See
[Configuration](configuration.md) for bind-mounted config and authorization
files.

## First engagement

1. Start the Kali bridge and Ollama.
2. Launch HydraSight:

   ```bash
   hydrasight
   ```

3. **Authorize your target scope** (nothing runs until you do):

   ```text
   hydra·sight › authorize 10.10.10.0/24
   ```

   You will be prompted to type `I AUTHORIZE` exactly.

4. Kick off an engagement:

   ```text
   hydra·sight › autopwn 10.10.10.15
   ```

See [Usage](usage.md) for the full command reference.
