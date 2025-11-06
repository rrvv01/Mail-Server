# -*- coding: utf-8 -*-

import os
import re
import io
import json
import time
import math
import zipfile
import hashlib
import zlib
import olefile
from threading import Thread

# ==========================
# 경로
# ==========================
ATTACH_DIR = "/home/goat/Maildir/attachments"
ZIP_OUT_DIR = "/home/goat/Maildir/zipfile"
RESULT_DIR = "/home/goat/Maildir/hwp_result"
os.makedirs(RESULT_DIR, exist_ok=True)

# ==========================
# 스코어 정책(조정 가능)
# ==========================
SCORE = {
    "not_ole_hwp": 3,                  # .hwp인데 OLE 아님
    "fileheader_encrypted": 3,         # HWP FileHeader의 암호화 비트
    "embedded_magic": 2,               # 임베디드 실행형/위험 포맷 매직 발견
    "embedded_wmf_extra": 2,           # WMF 추가 가중
    "eps_ops_mild": 2,                 # EPS 연산자(file/filter/putinterval 등)
    "eps_ops_danger": 3,               # EPS 연산자(exec/system/run 등)
    "eps_ops_after_decompress": 3,     # 압축 해제 후 EPS 연산자
    "high_entropy": 1,                 # 엔트로피 높음
    "large_blob": 1,                   # 대용량 바이너리
    "external_rels": 2,                # HWPX 외부 관계
    "url_ip": 2,                       # IP 기반 URL
    "url_shortener": 1,                # 단축 URL
    "url_nonstd_port": 1,              # 80/443 외 포트
    "hwp_ext_zip_treat_hwpx": 2,       # .hwp지만 ZIP이면 HWPX로 취급
    "hwp_ext_pe": 9,                   # .hwp인데 MZ(PE)
    "hwp_ext_eps": 0,                  # .hwp인데 EPS 원본(하단 EPS 가중과 합산)
    "parse_error": 1,                  # 파싱 에러
}
THRESHOLD_SUSPICIOUS = 4
THRESHOLD_MALICIOUS = 7

# ==========================
# 일반 탐지에 쓰는 상수/정규식
# ==========================
EXEC_MAGIC = [
    (b"MZ", "PE/EXE/DLL"),
    (b"PK\x03\x04", "ZIP/OOXML/Office/Pkg"),
    (b"7z\xBC\xAF\x27\x1C", "7z"),
    (b"Rar!\x1A\x07\x00", "RAR4"),
    (b"Rar!\x1A\x07\x01\x00", "RAR5"),
    (b"%!PS", "PostScript/EPS"),
    (b"\xD7\xCD\xC6\x9A", "WMF"),                 # Aldus Placeable (LE)
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE"), # CFB
]
SUS_EXT = {".exe", ".dll", ".js", ".jse", ".vbs", ".vbe", ".cmd", ".bat", ".ps1", ".scr", ".chm", ".lnk"}
SHORT_DOMAINS = {"bit.ly","t.co","tinyurl.com","goo.gl","is.gd","ow.ly","cutt.ly","rebrand.ly","buff.ly"}

URL_ASCII_RE = re.compile(rb"https?://[^\s\"'<>()]+", re.I)
URL_UTF16LE_RE = re.compile(rb"h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00[^\x00\s\"'<>()]+", re.I)
IP_URL_RE = re.compile(r"^https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)", re.I)

# EPS/PostScript 위험 연산자
EPS_PATTERNS = [
    b"currentfile", b"eexec", b"exec", b"run",
    b"file", b"deletefile", b"renamefile", b"system",
    b"ASCIIHexDecode", b"ASCII85Decode", b"SubFileDecode",
    b"putinterval", b"setfileposition", b"filter",
    b"/OutputFile", b"%pipe",
]
DANG_EPS = {"exec","system","run"}
MILD_EPS = {"file","filter","putinterval"}

# ==========================
# 유틸
# ==========================
def _read_head(b: bytes, n=8):
    return b[:n] if len(b) >= n else b

def _magic_tag(b: bytes):
    head = _read_head(b, 8)
    for sig, name in EXEC_MAGIC:
        if head.startswith(sig):
            return name
    return None

def _entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    freq = [0]*256
    for c in sample:
        freq[c] += 1
    ent = 0.0
    l = float(len(sample))
    for f in freq:
        if f:
            p = f/l
            ent -= p*math.log(p, 2)
    return ent

def _collect_urls(buf: bytes):
    urls = []
    for m in URL_ASCII_RE.findall(buf):
        try: urls.append(m.decode("utf-8","ignore"))
        except: pass
    for m in URL_UTF16LE_RE.findall(buf):
        try: urls.append(m.decode("utf-16le","ignore"))
        except: pass
    return urls

def _sanitize_url(u: str) -> str:
    u = u.split('\x00')[0]
    u = re.split(r'[\s\r\n\t]', u)[0]
    if not u.lower().startswith(('http://','https://')):
        return ''
    return u

def _classify_url(u: str):
    cls = {"is_ip": False, "is_short": False, "has_nonstd_port": False}
    try:
        low = u.lower()
        rhs = low.split("//",1)[1] if "://" in low else low
        host = re.split(r"/|\?", rhs)[0]
        # IP
        if IP_URL_RE.match(u):
            cls["is_ip"] = True
        # 포트
        if ":" in host:
            try:
                port = int(host.split(":")[1])
                if port not in (80, 443): cls["has_nonstd_port"] = True
            except: pass
        # 단축
        host0 = host.split(":")[0]
        if host0 in SHORT_DOMAINS:
            cls["is_short"] = True
    except: pass
    return cls

def _scan_eps_ops(buf: bytes):
    hits = []
    low = buf.lower()
    for p in EPS_PATTERNS:
        if p.lower() in low:
            hits.append(p.decode("ascii", "ignore"))
    return hits

def _maybe_zlib_decompress(b: bytes) -> bytes:
    for wbits in (-15, 15):
        try:
            return zlib.decompress(b, wbits)
        except Exception:
            pass
    return b""

def _score_eps(res: dict, ops: list, where: str):
    if not ops: return
    ops_set = set(op.lower() for op in ops)
    add = 0
    if ops_set & DANG_EPS: add += SCORE["eps_ops_danger"]
    if ops_set & MILD_EPS: add += SCORE["eps_ops_mild"]
    if add:
        res["indicators"].append(f"Warn: EPS ops in {where}: {', '.join(sorted(ops_set))}")
        res["score"] += add

def _save_result(base_path, result):
    base = os.path.basename(base_path)
    out = os.path.join(RESULT_DIR, f"{base}_hwp.json")
    with open(out, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    print(f"[HWP Analyzer] saved: {out}")

# ==========================
# 판별
# ==========================
def is_hwp(path: str):
    try:
        if olefile.isOleFile(path):
            with olefile.OleFileIO(path) as ole:
                return ole.exists("FileHeader") or any("HwpSummaryInformation" in "/".join(i) for i in ole.listdir())
    except: pass
    return False

def is_hwpx_by_ext_magic(path: str):
    # 확장자나 매직으로 ZIP 확인(.hwpx는 ZIP 기반)
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except: return False

# ==========================
# 분석: HWP(OLE)
# ==========================
def analyze_hwp(path: str):
    res = {
        "file": os.path.basename(path),
        "type": "HWP",
        "indicators": [],
        "bin_hits": [],
        "links": [],
        "structure": {
            "streams": 0, "storages": 0, "body_sections": 0,
            "has_docinfo": False, "has_summaryinfo": False,
            "bindata_count": 0, "ole_like_count": 0
        },
        "score": 0,
        "classification": "benign",
    }
    try:
        if not olefile.isOleFile(path):
            res["indicators"].append("Warn: Not an OLE container (unexpected for .hwp)")
            res["score"] += SCORE["not_ole_hwp"]
            sc = min(10, max(0, res["score"]))
            res["score"] = sc
            res["classification"] = "malicious" if sc>=THRESHOLD_MALICIOUS else "suspicious" if sc>=THRESHOLD_SUSPICIOUS else "benign"
            return res

        with olefile.OleFileIO(path) as ole:
            entries = ole.listdir(streams=True, storages=True)
            streams = [e for e in entries if ole.exists(e) and ole.get_type(e)==olefile.STGTY_STREAM]
            storages = [e for e in entries if ole.exists(e) and ole.get_type(e)==olefile.STGTY_STORAGE]
            res["structure"]["streams"]  = len(streams)
            res["structure"]["storages"] = len(storages)
            res["structure"]["body_sections"] = sum(1 for e in entries if "/".join(e).startswith("BodyText/Section"))
            res["structure"]["has_docinfo"] = ole.exists("DocInfo")
            if any("HwpSummaryInformation" in "/".join(e) for e in entries):
                res["structure"]["has_summaryinfo"] = True

            # FileHeader 플래그
            if ole.exists("FileHeader"):
                try:
                    fh = ole.openstream("FileHeader").read()
                    res["indicators"].append(f"Info: FileHeader present (size={len(fh)})")
                    if len(fh) >= 0x38:
                        flag = fh[0x34] | (fh[0x35]<<8) | (fh[0x36]<<16) | (fh[0x37]<<24)
                        if flag & 0x10:
                            res["indicators"].append("Warn: Encryption flag set in FileHeader (0x10)")
                            res["score"] += SCORE["fileheader_encrypted"]
                except Exception as e:
                    res["indicators"].append(f"Info: FileHeader read error: {e}")

            bindata_cnt = 0
            ole_like_cnt = 0

            for e in entries:
                p = "/".join(e)
                if ole.exists(e) and ole.get_type(e)==olefile.STGTY_STREAM:
                    try:
                        b = ole.openstream(e).read(262144)

                        # URL 수집
                        urls = _collect_urls(b)
                        if urls: res["links"].extend(urls)

                        # FileHeader는 EPS 스캔 제외(오탐 회피)
                        is_fileheader = (p == "FileHeader" or p.lower().endswith("/fileheader"))

                        # EPS 스캔
                        if not is_fileheader:
                            _score_eps(res, _scan_eps_ops(b), f"stream {p}")

                        # 매직
                        tag = _magic_tag(b)
                        if tag:
                            res["bin_hits"].append({"stream": p, "tag": tag})
                            lt = tag.lower()
                            if any(t in lt for t in ["pe","exe","dll","script","postscript","wmf","ole","zip","7z","rar"]):
                                res["score"] += SCORE["embedded_magic"]
                                if "wmf" in lt:
                                    res["indicators"].append("Warn: Embedded WMF detected")
                                    res["score"] += SCORE["embedded_wmf_extra"]

                        # 엔트로피/사이즈(주로 BinData/객체)
                        if any(k in p.lower() for k in ["bindata","object","ole","package"]):
                            ent = _entropy(b[:131072])
                            if ent >= 7.5:
                                res["indicators"].append(f"Info: High entropy blob in {p} (>=7.5)")
                                res["score"] += SCORE["high_entropy"]
                            if len(b) >= 200*1024:
                                res["indicators"].append(f"Info: Large embedded blob in {p} (>=200KB)")
                                res["score"] += SCORE["large_blob"]

                        # zlib 해제 후 재스캔
                        dz = _maybe_zlib_decompress(b)
                        if dz:
                            urls2 = _collect_urls(dz)
                            if urls2:
                                res["indicators"].append(f"Info: URLs found after zlib decompress in {p} (count={len(urls2)})")
                                res["links"].extend(urls2)
                            if not is_fileheader:
                                ops2 = _scan_eps_ops(dz)
                                if ops2:
                                    res["indicators"].append(f"Warn: EPS ops after decompress in {p}: {', '.join(sorted(set(ops2)))}")
                                    res["score"] += SCORE["eps_ops_after_decompress"]
                                    _score_eps(res, ops2, f"stream {p} (decompressed)")
                    except Exception:
                        pass

                # 카운터
                if any(k in p.lower() for k in ["bindata"]): bindata_cnt += 1
                elif any(k in p.lower() for k in ["object","ole","package"]): ole_like_cnt += 1

            res["structure"]["bindata_count"] = bindata_cnt
            res["structure"]["ole_like_count"] = ole_like_cnt

            # URL 정리/일반 위험 신호 가중
            if res["links"]:
                cleaned = [u for u in (_sanitize_url(x) for x in res["links"]) if u]
                dedup = list(dict.fromkeys(cleaned))
                res["links"] = dedup
                hints = 0
                for u in dedup:
                    c = _classify_url(u)
                    if c["is_ip"]:
                        res["indicators"].append(f"Warn: IP-based URL {u}")
                        res["score"] += SCORE["url_ip"]; hints += 1
                    if c["is_short"]:
                        res["indicators"].append(f"Info: Shortened URL {u}")
                        res["score"] += SCORE["url_shortener"]; hints += 1
                    if c["has_nonstd_port"]:
                        res["indicators"].append(f"Info: Non-standard port in URL {u}")
                        res["score"] += SCORE["url_nonstd_port"]; hints += 1
                res["indicators"].append(f"Info: Found {len(dedup)} URL(s), suspicious hints={hints}")

            # 구조 요약
            res["indicators"].append(
                f"Info: Streams={res['structure']['streams']}, Storages={res['structure']['storages']}, "
                f"BodyText sections={res['structure']['body_sections']}, BinData={bindata_cnt}, OleLike={ole_like_cnt}"
            )

    except Exception as e:
        res["indicators"].append(f"Parse error: {e}")
        res["score"] += SCORE["parse_error"]

    sc = min(10, max(0, res["score"]))
    res["score"] = sc
    res["classification"] = "malicious" if sc>=THRESHOLD_MALICIOUS else "suspicious" if sc>=THRESHOLD_SUSPICIOUS else "benign"
    return res

# ==========================
# 분석: HWPX(OPC+ZIP)
# ==========================
def analyze_hwpx(path: str):
    res = {
        "file": os.path.basename(path),
        "type": "HWPX",
        "indicators": [],
        "bin_hits": [],
        "links": [],
        "structure": {"entries": 0, "bindata_count": 0, "external_rels": 0},
        "score": 0,
        "classification": "benign",
    }
    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            res["structure"]["entries"] = len(names)

            for n in names:
                nl = n.lower()
                # 바이너리 후보
                if nl.startswith(("bindata/","binarystore/","embeddings/")) or nl.endswith((".bin",".ole",".dat",".ps",".eps",".wmf",".bmp",".jpg",".jpeg",".png",".gif",".tif",".emf")):
                    try:
                        with z.open(n) as f:
                            b = f.read(262144)
                        tag = _magic_tag(b)
                        if tag:
                            res["bin_hits"].append({"file": n, "tag": tag})
                            lt = tag.lower()
                            if any(t in lt for t in ["pe","exe","dll","script","postscript","wmf","ole","zip","7z","rar"]):
                                res["score"] += SCORE["embedded_magic"]
                                if "wmf" in lt:
                                    res["indicators"].append("Warn: Embedded WMF detected")
                                    res["score"] += SCORE["embedded_wmf_extra"]
                        # EPS
                        _score_eps(res, _scan_eps_ops(b), f"file {n}")
                        # 엔트로피/사이즈
                        ent = _entropy(b[:131072])
                        if ent >= 7.5:
                            res["indicators"].append(f"Info: High entropy blob in {n} (>=7.5)")
                            res["score"] += SCORE["high_entropy"]
                        if len(b) >= 200*1024:
                            res["indicators"].append(f"Info: Large embedded blob in {n} (>=200KB)")
                            res["score"] += SCORE["large_blob"]
                        # 위험 확장자
                        ext = os.path.splitext(n)[1].lower()
                        if ext in SUS_EXT:
                            res["indicators"].append(f"Warn: Suspicious embedded file ext {n}")
                            res["score"] += SCORE["embedded_magic"]
                        res["structure"]["bindata_count"] += 1
                    except Exception:
                        pass

            # XML/.rels: URL + External
            for n in names:
                if n.lower().endswith((".rels",".xml")):
                    try:
                        with z.open(n) as f:
                            b = f.read()
                        if b'TargetMode="External"' in b or b"TargetMode='External'" in b:
                            res["indicators"].append(f"Warn: External relationship in {n}")
                            res["structure"]["external_rels"] += 1
                            res["score"] += SCORE["external_rels"]
                        res["links"].extend(_collect_urls(b))
                    except Exception:
                        pass

            # URL 정리/일반 위험 신호
            if res["links"]:
                cleaned = [u for u in (_sanitize_url(x) for x in res["links"]) if u]
                dedup = list(dict.fromkeys(cleaned))
                res["links"] = dedup
                hints = 0
                for u in dedup:
                    c = _classify_url(u)
                    if c["is_ip"]:
                        res["indicators"].append(f"Warn: IP-based URL {u}")
                        res["score"] += SCORE["url_ip"]; hints += 1
                    if c["is_short"]:
                        res["indicators"].append(f"Info: Shortened URL {u}")
                        res["score"] += SCORE["url_shortener"]; hints += 1
                    if c["has_nonstd_port"]:
                        res["indicators"].append(f"Info: Non-standard port in URL {u}")
                        res["score"] += SCORE["url_nonstd_port"]; hints += 1
                res["indicators"].append(f"Info: Found {len(dedup)} URL(s), suspicious hints={hints}")

            # 구조 요약
            res["indicators"].append(
                f"Info: Entries={res['structure']['entries']}, BinData={res['structure']['bindata_count']}, ExternalRels={res['structure']['external_rels']}"
            )

    except zipfile.BadZipFile:
        res["indicators"].append("Warn: Not a valid HWPX (zip)")
        res["score"] += SCORE["parse_error"]
    except Exception as e:
        res["indicators"].append(f"Parse error: {e}")
        res["score"] += SCORE["parse_error"]

    sc = min(10, max(0, res["score"]))
    res["score"] = sc
    res["classification"] = "malicious" if sc>=THRESHOLD_MALICIOUS else "suspicious" if sc>=THRESHOLD_SUSPICIOUS else "benign"
    return res

# ==========================
# 드라이버
# ==========================
def process_file(path: str):
    low = path.lower()
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except Exception:
        head = b""

    # .hwp / .hwpx 기본 라우팅 + 위장 처리
    if low.endswith(".hwp") or is_hwp(path):
        if head.startswith(b"PK\x03\x04"):
            r = analyze_hwpx(path)
            r["indicators"].append("Warn: File ext is .hwp but ZIP magic detected → treating as HWPX")
            r["score"] += SCORE["hwp_ext_zip_treat_hwpx"]
            _save_result(path, r); return
        if head.startswith(b"MZ"):
            out = {
                "file": os.path.basename(path),
                "type": "HWP(ext) / PE",
                "indicators": ["Warn: File ext is .hwp but PE/EXE magic (MZ) detected"],
                "bin_hits": [], "links": [], "structure": {},
                "score": SCORE["hwp_ext_pe"], "classification": "malicious"
            }
            _save_result(path, out); return
        if head.startswith(b"%!PS"):
            # .hwp로 위장된 EPS 원본
            b = open(path,"rb").read()
            out = {
                "file": os.path.basename(path), "type": "HWP(ext) / EPS",
                "indicators": [], "bin_hits": [], "links": _collect_urls(b), "structure": {},
                "score": SCORE["hwp_ext_eps"], "classification": "benign"
            }
            _score_eps(out, _scan_eps_ops(b), "raw file")
            dz = _maybe_zlib_decompress(b)
            if dz:
                _score_eps(out, _scan_eps_ops(dz), "raw file (decompressed)")
                out["links"].extend(_collect_urls(dz))
            if out["links"]:
                cleaned = [u for u in (_sanitize_url(x) for x in out["links"]) if u]
                out["links"] = list(dict.fromkeys(cleaned))
            sc = min(10, max(0, out["score"]))
            out["score"] = sc
            out["classification"] = "malicious" if sc>=THRESHOLD_MALICIOUS else "suspicious" if sc>=THRESHOLD_SUSPICIOUS else "benign"
            _save_result(path, out); return

        r = analyze_hwp(path)
        _save_result(path, r); return

    if low.endswith(".hwpx") or is_hwpx_by_ext_magic(path):
        r = analyze_hwpx(path)
        _save_result(path, r); return

    # 기타 파일은 참고용 태깅만
    out = {
        "file": os.path.basename(path),
        "type": "Unknown",
        "indicators": ["Info: Not an HWP/HWPX — skipped from this analyzer"],
        "bin_hits": [], "links": [], "structure": {},
        "score": 0, "classification": "benign"
    }
    _save_result(path, out)

def monitor_dirs():
    seen = set()
    while True:
        try:
            for root in (ATTACH_DIR, ZIP_OUT_DIR):
                for dirpath, _, files in os.walk(root):
                    for fn in files:
                        fp = os.path.join(dirpath, fn)
                        if not os.path.isfile(fp) or fp in seen: continue
                        seen.add(fp)
                        process_file(fp)
        except Exception as e:
            print(f"[HWP Analyzer] monitor error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    Thread(target=monitor_dirs, daemon=True).start()
    print("HWP/HWPX analyzer watching attachments & zipfile...")
    while True:
        time.sleep(3600)


