import email
from email import policy
from email.parser import BytesParser
import os
import threading
import time
import json
import datetime
import shutil

# ===== 경로 설정 =====
SPAMASSASSIN_HEADER_DIR = "/home/goat/Maildir/header"
CLAMAV_SCAN_LOG_PATH = "/home/goat/Maildir/scan_results.log"
FILE_SIGNATURE_LOG_PATH = "/home/goat/Maildir/check_hex.log"
FINAL_REPORT_DIR = "/home/goat/FinalReport"
NEW_MAIL_DIR = "/home/roat/Maildir/new"  # <- 의도 경로 확인
PROCESSED_MAIL_DIR = "/home/goat/Maildir/processed"
ATTACHMENTS_DIR = "/home/goat/Maildir/attachments"
EXTRACTED_FILES_DIR = "/home/goat/Maildir/attachments/extracted_files"
CUCKOO_REPORT_DIR = "/home/goat/report"
ML_RESULT_DIR = "/home/goat/Maildir/result_ml"
HWP_RESULT_DIR = "/home/goat/Maildir/hwp_result"

# ===== 유틸 =====
def safe_mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except FileNotFoundError:
        return 0

def list_cuckoo_jsons() -> list:
    try:
        return [f for f in os.listdir(CUCKOO_REPORT_DIR) if f.endswith(".json")]
    except FileNotFoundError:
        return []

def list_cuckoo_jsons_since(ts: float) -> list:
    """기준 시각(ts) 이후 mtime을 가진 Cuckoo JSON만 반환"""
    try:
        items = []
        for f in os.listdir(CUCKOO_REPORT_DIR):
            if not f.endswith(".json"):
                continue
            p = os.path.join(CUCKOO_REPORT_DIR, f)
            try:
                if os.path.getmtime(p) >= ts:
                    items.append(f)
            except FileNotFoundError:
                continue
        return items
    except FileNotFoundError:
        return []

def safe_listdir(path: str) -> list:
    try:
        return os.listdir(path)
    except FileNotFoundError:
        return []

# ===== HWP/HWPX: "이번 처리 도중 새로 생성/수정된" 결과만 포함 (중복 제거) =====
def _iter_hwp_json_paths_since(baseline_ts: float):
    if not os.path.isdir(HWP_RESULT_DIR):
        return
    for name in os.listdir(HWP_RESULT_DIR):
        if not name.endswith("_hwp.json"):
            continue
        p = os.path.join(HWP_RESULT_DIR, name)
        try:
            mtime = os.path.getmtime(p)
        except FileNotFoundError:
            continue
        if mtime >= baseline_ts:  # baseline 이후에 생성/수정된 파일만
            yield p

def hwp_ready_since(baseline_ts: float) -> bool:
    for _ in _iter_hwp_json_paths_since(baseline_ts):
        return True
    return False

def process_hwp_result_since(baseline_ts: float):
    """
    - baseline_ts 이후 생성/수정된 *_hwp.json만 읽음
    - type ∈ {HWP, HWPX}만 포함
    - 동일 file 항목은 1번만(중복 제거)
    - 결과 없으면 {} 반환
    """
    seen_files = set()
    filtered = []

    for path in _iter_hwp_json_paths_since(baseline_ts):
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
        except Exception:
            continue

        # 다양한 포맷 방어 처리
        candidates = []
        if isinstance(obj, dict) and "HWP/HWPX Analysis" in obj and isinstance(obj["HWP/HWPX Analysis"], list):
            candidates = obj["HWP/HWPX Analysis"]
        elif isinstance(obj, dict):
            candidates = [obj]
        elif isinstance(obj, list):
            candidates = obj

        for it in candidates:
            try:
                fpath = str(it.get("file", ""))
                ftype = str(it.get("type", "")).upper()
                if ftype not in ("HWP", "HWPX"):
                    continue
                if fpath and fpath not in seen_files:
                    seen_files.add(fpath)
                    filtered.append(it)
            except Exception:
                continue

    if not filtered:
        return {}

    worst = 0.0
    for it in filtered:
        try:
            worst = max(worst, float(it.get("score", 0)))
        except Exception:
            pass

    return {
        "HWP/HWPX Analysis": filtered,
        "HWP/HWPX WorstScore": worst,
    }

# ===== JSON 파일 저장 =====
def save_json_report(mail_filename, report_data):
    os.makedirs(FINAL_REPORT_DIR, exist_ok=True)
    base_filename = os.path.splitext(mail_filename)[0]
    filename = f"{base_filename}_FinalReport.json"
    filepath = os.path.join(FINAL_REPORT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as json_file:
        json.dump(report_data, json_file, indent=4, ensure_ascii=False)
    print(f"최종 보고서 저장됨: {filepath}")

# ===== SpamAssassin 처리 =====
def process_spamassassin(mail_filename):
    print("Processing SpamAssassin")
    report_data = {}

    base_filename = os.path.splitext(mail_filename)[0]
    header_filename = f"{base_filename}_header.txt"
    header_filepath = os.path.join(SPAMASSASSIN_HEADER_DIR, header_filename)

    if not os.path.exists(header_filepath):
        print(f"Header file not found: {header_filepath}")
        return {}

    with open(header_filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    spam_assassin_lines = []
    score = None
    required = None
    x_spam_status_line = ""

    for line in lines:
        if line.startswith("X-Spam-Checker-Version"):
            spam_assassin_lines.append(line.strip())
        elif line.startswith("X-Spam-Level"):
            spam_assassin_lines.append(line.strip())
        elif line.startswith("X-Spam-Status"):
            x_spam_status_line = line.strip()
        elif x_spam_status_line:
            x_spam_status_line += " " + line.strip()

    if x_spam_status_line:
        spam_assassin_lines.append(x_spam_status_line.split("tests=")[0].strip())
        try:
            parts = x_spam_status_line.split()
            score_part = [part for part in parts if part.startswith("score=")]
            required_part = [part for part in parts if part.startswith("required=")]
            if score_part and required_part:
                score = float(score_part[0].split("=")[1].split(",")[0])
                required = float(required_part[0].split("=")[1].split(",")[0])
        except (IndexError, ValueError) as e:
            print(f"Error parsing X-Spam-Status: {e}")
            score = None
            required = None

    if score is not None and required is not None:
        if score >= required:
            report_data["SpamAssassin"] = ["Warning"]
        else:
            report_data["SpamAssassin"] = ["Safe"]
    else:
        report_data["SpamAssassin"] = ["Safe"]
        spam_assassin_lines = ["화이트리스트에 등록된 발신자입니다"]

    report_data["SpamAssassinDetails"] = spam_assassin_lines
    return report_data

# ===== ClamAV 결과 파싱 =====
def parse_clamav_scan_results(start_line):
    results = []
    infected_files = 0
    if os.path.exists(CLAMAV_SCAN_LOG_PATH):
        with open(CLAMAV_SCAN_LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[start_line:]:
            results.append(line.strip())
            if "Infected files:" in line:
                try:
                    infected_files = int(line.strip().split(":")[1])
                except Exception:
                    pass
    return results, infected_files

# ===== File Signature 결과 파싱 =====
def parse_file_signature_results(start_line):
    results = []
    file_safe = False
    file_bypass = False
    if os.path.exists(FILE_SIGNATURE_LOG_PATH):
        with open(FILE_SIGNATURE_LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[start_line:]:
            s = line.strip()
            results.append(s)
            if "Safe" in s:
                file_safe = True
            if "Dangerous" in s:
                file_bypass = True
    return results, file_safe, file_bypass

# ===== Cuckoo 보고서 파싱(JSON) =====
def parse_cuckoo_report(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    cuckoo_data = {"CuckooDetails": []}
    info = data.get("info", {})
    signatures = data.get("signatures", [])

    score = info.get("score", "N/A")
    cuckoo_data["Cuckoo"] = [f"The score of this file is {score} out of 10."]

    for sig in signatures:
        ttp = sig.get("ttp", {})
        if isinstance(ttp, dict) and "long" in ttp:
            description = sig.get("description", "No description")
            long_text = ttp.get("long")
            cuckoo_data["CuckooDetails"].append(f"{description}: {long_text}")

    return cuckoo_data

# ===== Cuckoo 보고서에서 "long" 나오기 전 줄까지 추출 =====
def extract_until_long(filepath):
    lines = []
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            for line in file:
                lines.append(line.strip())
                if '"long":' in line:
                    break
    except Exception:
        pass
    return lines

# ===== ML 결과 처리 =====
def process_ml_result(mail_filename):
    base_filename = os.path.splitext(mail_filename)[0]
    ml_filename = f"result_{base_filename}_links.txt"
    ml_filepath = os.path.join(ML_RESULT_DIR, ml_filename)

    if not os.path.exists(ml_filepath):
        print(f"ML result file not found: {ml_filepath}")
        return {}

    with open(ml_filepath, "r", encoding="utf-8") as f:
        ml_lines = f.readlines()

    ml_details = [line.strip() for line in ml_lines]
    ml_summary = [line.strip() for line in ml_lines if "Random Forest" in line]

    report_data = {
        "ML": ml_summary if ml_summary else ["No Random Forest related content"],
        "ML Details": ml_details
    }
    return report_data

# ===== 메일 1건 처리 =====
def monitor_and_process(filepath):
    try:
        mail_filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
        sender = msg["from"]
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        print(f"Processing new email from {sender} at {timestamp}")

        # ---- HWP 기준 시각: 이 시각 이후 생성/수정된 HWP 결과만 포함 ----
        hwp_baseline_ts = time.time()

        # (monitor_and_process 내부, while 루프 직전과 동일하게) 기준시각 재사용
        cuckoo_baseline_ts = hwp_baseline_ts  # 이미 잡아둔 기준 시각 재사용

        # 현재 로그 파일의 라인 수 기록(새로 추가되는 라인만 파싱)
        start_line_clamav = 0
        start_line_signature = 0
        if os.path.exists(CLAMAV_SCAN_LOG_PATH):
            with open(CLAMAV_SCAN_LOG_PATH, "r", encoding="utf-8") as f:
                start_line_clamav = len(f.readlines())
        if os.path.exists(FILE_SIGNATURE_LOG_PATH):
            with open(FILE_SIGNATURE_LOG_PATH, "r", encoding="utf-8") as f:
                start_line_signature = len(f.readlines())

        # mtime 기준선
        last_log_modification_time_clamav = safe_mtime(CLAMAV_SCAN_LOG_PATH)
        last_log_modification_time_signature = safe_mtime(FILE_SIGNATURE_LOG_PATH)
        print(f"Initial ClamAV log modification time: {last_log_modification_time_clamav}")
        print(f"Initial Signature log modification time: {last_log_modification_time_signature}")

        idle_time = 0
        waited = 0
        MAX_WAIT = 600  # 최대 10분 대기
        cuckoo_report_detected = False
        hwp_ready = False

        while True:
            time.sleep(10)
            waited += 10

            # 로그 파일 변경 감지
            current_log_modification_time_clamav = safe_mtime(CLAMAV_SCAN_LOG_PATH)
            current_log_modification_time_signature = safe_mtime(FILE_SIGNATURE_LOG_PATH)
            if (current_log_modification_time_clamav == last_log_modification_time_clamav and
                current_log_modification_time_signature == last_log_modification_time_signature):
                idle_time += 10
            else:
                last_log_modification_time_clamav = current_log_modification_time_clamav
                last_log_modification_time_signature = current_log_modification_time_signature
                idle_time = 0

            # Cuckoo/HWP 준비 확인
            print("Checking for Cuckoo/HWP reports...")
            if not cuckoo_report_detected and list_cuckoo_jsons_since(cuckoo_baseline_ts):
                print("New Cuckoo JSON report detected.")
                cuckoo_report_detected = True

            if not hwp_ready and hwp_ready_since(hwp_baseline_ts):
                print("New HWP result detected for this processing window.")
                hwp_ready = True

            # 종료 조건: 3분 무변동 & (Cuckoo or HWP 새 결과 감지) 또는 최대대기 초과
            if ((idle_time >= 180) and (cuckoo_report_detected or hwp_ready)) or (waited >= MAX_WAIT):
                print("No modifications or timeout reached. Generating report...")
                break

        # 각 보고서 처리
        report_data = {}

        # SpamAssassin
        spamassassin_data = process_spamassassin(mail_filename)
        print(f"SpamAssassin data: {spamassassin_data}")
        report_data.update(spamassassin_data)

        # ClamAV
        clamav_results, infected_files = parse_clamav_scan_results(start_line_clamav)
        print(f"ClamAV results: {clamav_results}, Infected files: {infected_files}")
        if infected_files > 0:
            report_data["ClamAV"] = ["File contains virus/malware."]
        else:
            report_data["ClamAV"] = ["File scanned clean."]
        report_data["ClamAVDetails"] = clamav_results

        # File Signature
        file_signature_results, file_safe, file_bypass = parse_file_signature_results(start_line_signature)
        print(f"File Signature results: {file_signature_results}, File safe: {file_safe}, File bypass: {file_bypass}")
        if file_safe:
            report_data["File Signature"] = ["File is safe"]
        elif file_bypass:
            report_data["File Signature"] = ["File is bypass"]
        else:
            report_data["File Signature"] = ["Unknown"]
        report_data["File Signature Details"] = file_signature_results

        # ===== Cuckoo(JSON): 이번 처리 창 이후 생성된 리포트 중 '최신 1개'만 반영 =====
        cuckoo_jsons = list_cuckoo_jsons_since(cuckoo_baseline_ts)
        if cuckoo_jsons:
            latest = max(
                cuckoo_jsons,
                key=lambda name: os.path.getmtime(os.path.join(CUCKOO_REPORT_DIR, name))
            )
            report_filepath = os.path.join(CUCKOO_REPORT_DIR, latest)
            try:
                cuckoo_data = parse_cuckoo_report(report_filepath)
                report_data["Cuckoo"] = cuckoo_data.get("Cuckoo", [])
                initial_lines = extract_until_long(report_filepath)
                cuckoo_details = cuckoo_data.get("CuckooDetails", []) + initial_lines
                report_data["CuckooDetails"] = cuckoo_details
                print(f"[Cuckoo] picked latest report: {latest}")
            except Exception as e:
                print(f"Failed to parse Cuckoo JSON {latest}: {e}")
        else:
            print("No Cuckoo report found for this processing window.")

        # ML
        ml_data = process_ml_result(mail_filename)
        print(f"ML data: {ml_data}")
        report_data.update(ml_data)

        # HWP/HWPX: 이번 처리 동안 새로 생성/수정된 결과만 포함(중복 제거)
        hwp_data = process_hwp_result_since(hwp_baseline_ts)
        if hwp_data:
            report_data.update(hwp_data)
            print(f"HWP included: {len(hwp_data.get('HWP/HWPX Analysis', []))} items, worst={hwp_data.get('HWP/HWPX WorstScore')}")
        else:
            print("No new HWP items for this processing window.")

        # 최종 보고서 저장
        print("Generating final report...")
        print(f"Final report data keys: {list(report_data.keys())}")
        save_json_report(mail_filename, report_data)

        # 처리된 파일 이동
        os.makedirs(PROCESSED_MAIL_DIR, exist_ok=True)
        processed_path = os.path.join(PROCESSED_MAIL_DIR, os.path.basename(filepath))
        shutil.move(filepath, processed_path)
        print(f"Processed file moved to: {processed_path}")

    except Exception as e:
        print(f"Error during processing: {e}")
        raise  # 스택 트레이스 확인을 위해 재발생

# ===== 새 메일 감시 루프 =====
def process_new_mail():
    while True:
        try:
            for filename in safe_listdir(NEW_MAIL_DIR):
                if filename.endswith(".xyz"):
                    filepath = os.path.join(NEW_MAIL_DIR, filename)
                    print(f"Processing file: {filepath}")
                    monitor_and_process(filepath)
            time.sleep(1)
        except Exception as e:
            print(f"Error in process_new_mail: {e}")

# ===== 엔트리포인트 =====
if __name__ == "__main__":
    os.makedirs(PROCESSED_MAIL_DIR, exist_ok=True)
    t = threading.Thread(target=process_new_mail, daemon=True)
    t.start()
    print("메일 디렉토리 모니터링 시작...")
    # 메인 스레드 유지
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Stopped by user.")

