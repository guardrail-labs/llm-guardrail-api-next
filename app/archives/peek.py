from __future__ import annotations

import base64
import io
import tarfile
import zipfile
from typing import Dict, Iterable, List, Tuple

_MAX_BYTES = 256 * 1024  # 256 KiB hard cap for a single blob
_MAX_FILES = 64          # max entries listed per archive
_MAX_DEPTH = 2           # nested archives depth (0=top)
_MAX_SAMPLE = 4096       # text sample bytes collected per file

_TEXT_EXTS = {
    ".txt", ".md", ".csv", ".json", ".yaml", ".yml", ".xml", ".html", ".htm"
}
_ARCHIVE_HINTS = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2")

def _lc(s: str) -> str:
    return s.casefold()

def _is_probably_text(name: str) -> bool:
    n = _lc(name)
    for ext in _TEXT_EXTS:
        if n.endswith(ext):
            return True
    return False

def _is_archive_name(name: str) -> bool:
    n = _lc(name)
    return any(n.endswith(ext) for ext in _ARCHIVE_HINTS)

def _safe_b64(s: str) -> bytes | None:
    try:
        data = base64.b64decode(s, validate=True)
    except Exception:
        return None
    if not data or len(data) > _MAX_BYTES:
        return None
    return data

def _limit(items: Iterable[str], k: int) -> List[str]:
    out: List[str] = []
    for i, it in enumerate(items):
        if i >= k:
            break
        out.append(it)
    return out

def peek_zip(buf: bytes, depth: int = 0) -> Tuple[List[str], List[str], Dict[str, int]]:
    """
    Returns (filenames, text_samples, stats).
    depth is used to limit recursion of nested archives.
    """
    stats = {"files_listed": 0, "samples": 0, "nested_blocked": 0, "errors": 0}
    names: List[str] = []
    texts: List[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(buf)) as zf:
            for i, info in enumerate(zf.infolist()):
                if i >= _MAX_FILES:
                    break
                names.append(info.filename)
                stats["files_listed"] += 1
                # sample text files
                if _is_probably_text(info.filename) and not info.is_dir():
                    try:
                        with zf.open(info, "r") as fh:
                            data = fh.read(_MAX_SAMPLE)
                            try:
                                txt = data.decode("utf-8", errors="replace")
                            except Exception:
                                txt = ""
                            if txt:
                                texts.append(txt)
                                stats["samples"] += 1
                    except Exception:
                        stats["errors"] += 1
                # nested archives
                if depth < _MAX_DEPTH and _is_archive_name(info.filename):
                    try:
                        with zf.open(info, "r") as fh:
                            nb = fh.read(_MAX_BYTES)
                        if nb and len(nb) <= _MAX_BYTES:
                            nn, tt, st = peek_any(nb, info.filename, depth + 1)
                            names.extend(_limit(nn, max(0, _MAX_FILES - len(names))))
                            texts.extend(tt)
                            for k, v in st.items():
                                stats[k] = stats.get(k, 0) + v
                        else:
                            stats["nested_blocked"] += 1
                    except Exception:
                        stats["errors"] += 1
    except Exception:
        stats["errors"] += 1
    return names, texts, stats

def peek_tar(buf: bytes, depth: int = 0) -> Tuple[List[str], List[str], Dict[str, int]]:
    stats = {"files_listed": 0, "samples": 0, "nested_blocked": 0, "errors": 0}
    names: List[str] = []
    texts: List[str] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(buf), mode="r:*") as tf:
            for i, m in enumerate(tf.getmembers()):
                if i >= _MAX_FILES:
                    break
                names.append(m.name)
                stats["files_listed"] += 1
                if m.isfile() and _is_probably_text(m.name) and m.size <= _MAX_SAMPLE:
                    try:
                        f = tf.extractfile(m)
                        if f:
                            data = f.read(_MAX_SAMPLE)
                            try:
                                txt = data.decode("utf-8", errors="replace")
                            except Exception:
                                txt = ""
                            if txt:
                                texts.append(txt)
                                stats["samples"] += 1
                    except Exception:
                        stats["errors"] += 1
                if depth < _MAX_DEPTH and _is_archive_name(m.name) and m.size <= _MAX_BYTES:
                    try:
                        f = tf.extractfile(m)
                        if f:
                            nb = f.read(_MAX_BYTES)
                            if nb and len(nb) <= _MAX_BYTES:
                                nn, tt, st = peek_any(nb, m.name, depth + 1)
                                names.extend(
                                    _limit(nn, max(0, _MAX_FILES - len(names)))
                                )
                                texts.extend(tt)
                                for k, v in st.items():
                                    stats[k] = stats.get(k, 0) + v
                            else:
                                stats["nested_blocked"] += 1
                    except Exception:
                        stats["errors"] += 1
    except Exception:
        stats["errors"] += 1
    return names, texts, stats

def peek_any(buf: bytes, name_hint: str, depth: int = 0
             ) -> Tuple[List[str], List[str], Dict[str, int]]:
    n = _lc(name_hint)
    if n.endswith(".zip"):
        return peek_zip(buf, depth)
    if n.endswith((".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2")):
        return peek_tar(buf, depth)
    # Try zip first, then tar
    names, texts, stats = peek_zip(buf, depth)
    if stats.get("errors", 0):
        names2, texts2, stats2 = peek_tar(buf, depth)
        # prefer the one with fewer errors
        if stats2.get("errors", 0) < stats.get("errors", 0):
            return names2, texts2, stats2
    return names, texts, stats

def try_b64_archive(filename: str, b64: str
                    ) -> Tuple[List[str], List[str], Dict[str, int]]:
    """
    Convenience: base64 'content' + 'filename' fields.
    Returns (filenames, text_samples, stats). If invalid/oversized, returns empty.
    """
    data = _safe_b64(b64)
    if data is None:
        return [], [], {"errors": 1}
    return peek_any(data, filename, 0)
