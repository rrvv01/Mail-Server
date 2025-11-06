import email
from email import policy
import email.header
from email.parser import BytesParser
import os
import threading
import time
import requests
import json
import re
import unicodedata

# ===== Cuckoo API =====
REST_URL = "http://[쿠쿠샌드박스 서버 ip]:[지정 포트]/tasks/create/file"
GET_URL_BASE = "http://[쿠쿠샌드박스 서버 ip]:[지정 포트]/tasks/report/"
HEADERS = {"Authorization": "Bearer [쿠쿠샌드박스 API Token]"}

POST_TIMEOUT = 15       # 업로드 타임아웃(초)
GET_TIMEOUT = 10        # 리포트 조회 타임아웃(초)
POLL_INTERVAL = 30      # 리포트 폴링 간격(초)
FILE_SETTLE_SEC = 5     # 파일 mtime 안정화 대기(초)

# ===== 파일명 정리 =====
CONTROL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f]')

def sanitize_filename(name: str) -> str:
    if not name:
        return "attachment"
    name = unicodedata.normalize('NFC', name)
    name = CONTROL_CHARS_RE.sub('', name)
    name = name.replace('?', '')
    name = name.replace('\\', '_').replace('/', '_')
    name = re.sub(r'[^\w.\-() ]+', '', name)     # 안전 문자만 허용
    name = re.sub(r'\s+', ' ', name).strip().replace(' ', '_')  # 공백 -> _
    return (name or "attachment")[:120]          # 길이 제한

def safe_is_ready(path: str, settle: int = FILE_SETTLE_SEC) -> bool:
    """최근 수정 후 일정 시간 지난 파일만 처리"""
    try:
        return (time.time() - os.path.getmtime(path)) >= settle
    except Exception:
        return False

# ===== 업로드 =====
def process_file(filepath: str):
    # 원본 파일명으로 전송
    try:
        with open(filepath, "rb") as sample:
            files = {"file": (os.path.basename(filepath), sample)}
            r = requests.post(REST_URL, headers=HEADERS, files=files, timeout=POST_TIMEOUT)
    except requests.RequestException as e:
        print(f"[process_file] upload error: {filepath} :: {e}", flush=True)
        return

    if r.status_code != 200:
        print(f"[process_file] 작업 생성 실패({r.status_code}) :: {filepath}", flush=True)
        return

    task_id = r.json().get("task_id")
    print(f"[process_file] 작업 생성 성공! task_id={task_id} :: {filepath}", flush=True)

    # 폴링
    while True:
        try:
            get_url = GET_URL_BASE + str(task_id)
            gr = requests.get(get_url, headers=HEADERS, timeout=GET_TIMEOUT)
        except requests.RequestException as e:
            print(f"[process_file] report poll error task={task_id} :: {e}", flush=True)
            time.sleep(POLL_INTERVAL)
            continue

        if gr.status_code == 200:
            report_data = gr.json()
            report_dir = "/home/goat/report"
            os.makedirs(report_dir, exist_ok=True)
            report_filename = os.path.join(report_dir, f"{task_id}_report.json")
            with open(report_filename, "w") as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            print(f"[process_file] 보고서 저장: {report_filename}", flush=True)
            break
        else:
            print(f"[process_file] GET {gr.status_code}, {POLL_INTERVAL}s 후 재시도 (task={task_id})", flush=True)
            time.sleep(POLL_INTERVAL)

# ===== 첨부 추출 =====
def extract_attachments(eml_path: str, output_dir: str, processed_paths: set, processed_eml: set):
    # 파일 안정화 대기
    if not safe_is_ready(eml_path):
        return

    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    unique_id = os.path.basename(eml_path).split('.')[0]
    saved_any = False

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue

        attachment_filename = part.get_filename()
        if not attachment_filename:
            continue

        # RFC 2231 decode
        decoded = email.header.decode_header(attachment_filename)
        attachment_filename = ''.join(
            [t[0].decode(t[1] or 'utf-8', 'replace') if isinstance(t[0], (bytes, bytearray)) else t[0]
             for t in decoded]
        )
        attachment_filename = sanitize_filename(attachment_filename)

        final_name = f"{unique_id}.{attachment_filename}"
        save_path = os.path.join(output_dir, final_name)

        # 이미 처리했는지(경로 기준) 체크
        if save_path in processed_paths:
            continue

        # 처리 마킹을 먼저!
        processed_paths.add(save_path)

        # 저장
        try:
            with open(save_path, 'wb') as outf:
                outf.write(part.get_payload(decode=True))
            print(f"Attachment saved: {save_path}", flush=True)
            saved_any = True
        except Exception as e:
            print(f"[extract_attachments] save error {save_path}: {e}", flush=True)
            continue

        # 압축 확장자는 업로드 생략
        if not final_name.lower().endswith(('.zip', '.7z', '.alzip')):
            try:
                process_file(save_path)
            except Exception as e:
                print(f"[extract_attachments] process_file error {save_path}: {e}", flush=True)

    if saved_any:
        processed_eml.add(os.path.basename(eml_path))

# ===== 디렉토리 모니터링 =====
def monitor_dir(eml_dir: str, output_dir: str, processed_paths: set, processed_eml: set):
    # 부팅 시 기존 첨부 파일들을 처리완료로 마킹
    try:
        for fname in os.listdir(output_dir):
            processed_paths.add(os.path.join(output_dir, fname))
    except Exception as e:
        print(f"[monitor_dir] init error: {e}", flush=True)

    while True:
        try:
            candidates = [f for f in os.listdir(eml_dir) if f.endswith(".xyz")]
            # 이미 처리한 EML 제외
            new_emls = [f for f in candidates if f not in processed_eml]
            for fname in new_emls:
                eml_path = os.path.join(eml_dir, fname)
                try:
                    extract_attachments(eml_path, output_dir, processed_paths, processed_eml)
                except Exception as fe:
                    print(f"[monitor_dir] file error {fname}: {fe}", flush=True)
        except Exception as e:
            print(f"[monitor_dir] loop error: {e}", flush=True)
        time.sleep(1)

def monitor_files_in_dir(directory: str, processed_paths: set):
    while True:
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path in processed_paths:
                        continue
                    if not safe_is_ready(file_path):
                        continue
                    # 먼저 마킹
                    processed_paths.add(file_path)
                    try:
                        process_file(file_path)
                    except Exception as fe:
                        print(f"[zip-monitor] file error {file_path}: {fe}", flush=True)
        except Exception as e:
            print(f"[zip-monitor] loop error: {e}", flush=True)
        time.sleep(1)

# ===== Main =====
if __name__ == "__main__":
    eml_dir = "/home/roat/Maildir/new"
    attachments_dir = "/home/goat/Maildir/attachments"
    zipfile_dir = "/home/roat/Maildir/zipfile"

    processed_paths = set()   # 첨부/zip 경로 기준 중복 방지
    processed_eml = set()     # EML 파일명 기준 중복 방지

    t1 = threading.Thread(target=monitor_dir, args=(eml_dir, attachments_dir, processed_paths, processed_eml))
    t1.start()

    t2 = threading.Thread(target=monitor_files_in_dir, args=(zipfile_dir, processed_paths))
    t2.start()

    print("Monitoring email directory and zipfile directory...", flush=True)

