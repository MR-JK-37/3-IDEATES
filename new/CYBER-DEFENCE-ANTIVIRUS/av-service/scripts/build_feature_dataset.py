#!/usr/bin/env python3
"""
Build a training CSV from benign/malicious sample folders.

Output columns:
entropy,executable_ext,script_ext,doc_or_media_ext,valid_pe,embedded_pe,obfuscation,suspicious_strings,label,path
"""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    e = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        e -= p * math.log2(p)
    return e / 8.0


def ext_flags(path: Path) -> tuple[int, int, int]:
    ext = path.suffix.lower().lstrip(".")
    executable = int(ext in {"exe", "dll", "sys", "so", "bin", "run", "elf", "msi", "apk"})
    script = int(ext in {"ps1", "js", "vbs", "bat", "cmd", "sh", "py", "rb"})
    doc_media = int(
        ext
        in {
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "txt",
            "md",
            "rtf",
            "png",
            "jpg",
            "jpeg",
            "gif",
            "webp",
            "bmp",
            "svg",
            "mp3",
            "mp4",
        }
    )
    return executable, script, doc_media


def has_valid_pe(data: bytes) -> int:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return 0
    off = int.from_bytes(data[0x3C:0x40], "little")
    if off + 4 > len(data):
        return 0
    return int(data[off : off + 4] == b"PE\x00\x00")


def has_embedded_pe(data: bytes) -> int:
    upper = min(len(data), 128 * 1024)
    for i in range(512, max(512, upper - 4)):
        if data[i : i + 2] == b"MZ":
            wnd = min(upper, i + 512)
            for j in range(i + 2, max(i + 2, wnd - 4)):
                if data[j : j + 4] == b"PE\x00\x00":
                    return 1
    return 0


def obfuscation_score(text: str) -> int:
    markers = [
        "string.fromcharcode",
        "eval(",
        "frombase64string(",
        "invoke-expression",
        "runtime.getruntime",
        "createobject(",
    ]
    t = text.lower()
    return int(sum(1 for m in markers if m in t) >= 2)


def suspicious_strings_score(text: str) -> float:
    patterns = [
        "cmd.exe",
        "powershell",
        "createprocess",
        "createremotethread",
        "writeprocessmemory",
        "loadlibrary",
        "winexec",
        "shell_execute",
    ]
    t = text.lower()
    hits = sum(1 for p in patterns if p in t)
    return min(hits / 16.0, 1.0)


def file_rows(root: Path, label: int, max_bytes: int):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()[:max_bytes]
        except Exception:
            continue
        text = data.decode("utf-8", errors="ignore")
        exe, script, doc_media = ext_flags(p)
        yield {
            "entropy": entropy(data),
            "executable_ext": exe,
            "script_ext": script,
            "doc_or_media_ext": doc_media,
            "valid_pe": has_valid_pe(data),
            "embedded_pe": has_embedded_pe(data),
            "obfuscation": obfuscation_score(text),
            "suspicious_strings": suspicious_strings_score(text),
            "label": label,
            "path": str(p),
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-dir", required=True)
    ap.add_argument("--malicious-dir", required=True)
    ap.add_argument("--output", default="data/training/features.csv")
    ap.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024)
    args = ap.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "entropy",
        "executable_ext",
        "script_ext",
        "doc_or_media_ext",
        "valid_pe",
        "embedded_pe",
        "obfuscation",
        "suspicious_strings",
        "label",
        "path",
    ]

    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in file_rows(Path(args.benign_dir), 0, args.max_bytes):
            w.writerow(row)
        for row in file_rows(Path(args.malicious_dir), 1, args.max_bytes):
            w.writerow(row)

    print(f"saved {out}")


if __name__ == "__main__":
    main()
