YARA Setup and Enabling

This project supports YARA-based detection via the `yara-python` bindings and a `rules/` directory containing `.yar`/.yara` rules.

Important: `yara-python` depends on the system `libyara` C library. If `import yara` fails, follow the platform instructions below to install system dependencies first.

Ubuntu / Debian:

```bash
sudo apt update
sudo apt install -y build-essential libtool automake pkg-config python3-dev libjansson-dev libpcre3-dev libssl-dev
# build libyara from source (recommended) or install package
sudo apt install -y yara libyara-dev || true
# then in project venv
.venv/bin/pip install -r requirements_backend.txt
```

Fedora / CentOS:

```bash
sudo dnf install -y yara-devel pkgconfig gcc python3-devel jansson-devel pcre-devel openssl-devel
.venv/bin/pip install -r requirements_backend.txt
```

macOS (Homebrew):

```bash
brew install yara
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements_backend.txt
```

Verify installation in the project venv:

```bash
source .venv/bin/activate
python -c "import yara; print('yara', yara.__version__)"
```

Rules directory

- Place your YARA `.yar` or `.yara` rule files into the project `rules/` directory. The engine loads and compiles them at startup.
- Example rule: `rules/Ransomware_Generic.yar` is included as a starting point.

Behavior when YARA is unavailable

- The engine logs that YARA is unavailable and continues operating using entropy, signatures, and threat-intel.
- YARA-based detection is optional but recommended for higher-fidelity detections.

Security note

- YARA rules may contain patterns that match sensitive content. Ensure rules are trusted and reviewed before deploying in production.
