import pymysql
import re
import os
import json
import threading
import time
import email
import email.header
import email.utils

# MySQL 데이터베이스 연결
try:
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password='5543',
        database='maildb'
    )
    print("Database connection successful", flush=True)
except pymysql.MySQLError as e:
    print(f"Error connecting to database: {e}", flush=True)
    exit(1)

# 디렉토리 경로 설정
final_report_dir = '/home/goat/FinalReport'
processed_dir = '/home/goat/Maildir/processed'
header_dir = '/home/goat/Maildir/header'


# ===== 유틸 함수 =====
def decode_header(header_value):
    decoded_parts = email.header.decode_header(header_value)
    return ''.join([part.decode(encoding or 'utf-8') if isinstance(part, bytes) else part for part, encoding in decoded_parts])


def extract_sender_recipient(header):
    # From: (대소문자/공백 허용, 멀티라인 안전)
    sender_match = re.search(r'(?im)^\s*From\s*:\s*(.+)$', header)
    sender = decode_header(sender_match.group(1).strip()) if sender_match else None

    # To: "이름" <addr> | <addr> | addr  ← 모두 허용
    to_match = re.search(
        r'(?im)^\s*To\s*:\s*(?:(?:"[^"]*"\s*)?<([^>]+)>|([^\s<>]+@[^\s<>]+))',
        header
    )

    recipient = None
    if to_match:
        # 그룹1(<addr>) 또는 그룹2(plain addr) 중 존재하는 값 사용
        recipient = (to_match.group(1) or to_match.group(2)).strip()
    else:
        # 폴백 1: Delivered-To / X-Original-To / Envelope-To
        alt_match = re.search(
            r'(?im)^\s*(?:Delivered-To|X-Original-To|Envelope-To|X-Envelope-To)\s*:\s*([^\s<>]+@[^\s<>]+)',
            header
        )
        if alt_match:
            recipient = alt_match.group(1).strip()
        else:
            # 폴백 2: Received: ... for <addr>
            m_for = re.search(r'(?is)^\s*Received:.*?\bfor\s+<([^>]+)>\b', header)
            if m_for:
                recipient = m_for.group(1).strip()

    print(f"Extracted sender: {sender}", flush=True)
    print(f"Extracted recipient: {recipient}", flush=True)
    return sender, recipient



def extract_subject(header):
    subject_match = re.search(r'Subject: (.+)', header)
    subject = decode_header(subject_match.group(1)) if subject_match else None
    print(f"Extracted subject: {subject}", flush=True)
    return subject


def extract_received_date(header):
    received_dates = re.findall(r'Received:.*?; ([^;]+)', header, re.IGNORECASE | re.DOTALL)
    if received_dates:
        for date_str in received_dates:
            date_str = date_str.strip()
            print(f"Raw date string: {date_str}", flush=True)
            # (KST) 등 주석 제거
            date_str = re.sub(r'\s+\+\d{4}\s+\(.*?\)', '', date_str)
            try:
                date_obj = email.utils.parsedate_to_datetime(date_str)
                return date_obj.strftime("%Y-%m-%d %H:%M:%S.%f")
            except Exception as e:
                print(f"Date parsing error: {e}", flush=True)
    return None


# ===== JSON 파싱 =====
def parse_json_file(file_path):
    try:
        # BOM 포함 대비하여 직접 읽기
        with open(file_path, 'r', encoding='utf-8') as file:
            raw = file.read()
        if raw.startswith('\ufeff'):
            raw = raw.lstrip('\ufeff')
        data = json.loads(raw)

        # SpamAssassin
        spamassassin_status = "Safe" if "SpamAssassin" in data and "Safe" in str(data["SpamAssassin"]) else "Not Safe"

        # ClamAV
        clamav_status = None
        if "ClamAV" in data and data["ClamAV"]:
            clamav_status = data["ClamAV"][0]

        # File Signature
        file_signature_status = None
        if "File Signature" in data:
            file_signature_status = "File is safe" if "File is safe" in str(data["File Signature"]) else "Not Safe"

        # Cuckoo (기본 0.0: 0.0도 저장)
        cuckoo_score = 0.0
        if "Cuckoo" in data and data["Cuckoo"]:
            match = re.search(r"(\d+\.\d+)", str(data["Cuckoo"][0]))
            if match:
                cuckoo_score = float(match.group(1))

        # HWP/HWPX: 분석 배열 탐색 → malicious / suspicious / safe 구분
        hwp_status = None
        hwp_key = None
        # 키가 정확히 "HWP/HWPX Analysis" 로 온다고 했으니 우선 그 키부터
        if "HWP/HWPX Analysis" in data:
            hwp_key = "HWP/HWPX Analysis"
        else:
            # 혹시 다른 변형 키 지원(방어적)
            for k in data.keys():
                if "HWP" in k and "Analysis" in k:
                    hwp_key = k
                    break

        if hwp_key and isinstance(data.get(hwp_key), list):
            analyses = data[hwp_key]
            hwp_status = "Safe"  # 기본값
            for item in analyses:
                try:
                    cls = str(item.get("classification", "")).lower()
                    if cls == "malicious":
                        hwp_status = "Dangerous"
                        break  # 최상위 위험도 발견 → 종료
                    elif cls == "suspicious":
                        # malicious보다 한 단계 낮으므로 계속 탐색하여 malicious이 있는지 확인
                        if hwp_status != "Dangerous":
                            hwp_status = "Suspicious"
                except Exception:
                    continue
        # else: hwp_status는 None 그대로 두어도 되고, 필요시 기본값 "Safe"로 강제 가능

        # JSON 원문 보관(한글 그대로)
        json_content = json.dumps(data, ensure_ascii=False)

        # spamd, clamav, file_signature, cuckoo, hwp_status, json_content
        return spamassassin_status, clamav_status, file_signature_status, cuckoo_score, hwp_status, json_content

    except Exception as e:
        print(f"Error parsing JSON file {file_path}: {e}", flush=True)
        return None, None, None, None, None, None


# ===== DB 삽입 =====
def insert_email_info(sender, recipient, subject, received_date, spamd, clamav, file_signature, cuckoo, hwp_status, json_content):
    try:
        with connection.cursor() as cursor:
            connection.ping(reconnect=True)  # 세션 끊김 대비
            # ⚠️ 컬럼명에 슬래시가 있으므로 반드시 백틱
            sql = """
                INSERT INTO result_emails
                (Sender, recipient, subject, Received_date, Spamd, ClamAV, Cuckoo, `HWP/HWPX`, `File Signature`, `json`)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                sender, recipient, subject, received_date,
                spamd, clamav, cuckoo, hwp_status, file_signature, json_content
            ))
        connection.commit()
        print("Inserted email info into database", flush=True)
    except pymysql.MySQLError as e:
        print(f"Error: {e}", flush=True)


# ===== 파일 처리 =====
def process_json_file(file_number, sender, recipient, subject, received_date):
    final_report_file = None
    for fr_file in os.listdir(final_report_dir):
        if fr_file.startswith(file_number) and fr_file.endswith('_FinalReport.json'):
            final_report_file = os.path.join(final_report_dir, fr_file)
            break

    if not final_report_file or not os.path.exists(final_report_file):
        print(f"JSON 파일이 존재하지 않습니다: {final_report_file}", flush=True)
        return

    try:
        print(f"Processing JSON file: {final_report_file}", flush=True)
        spamd, clamav, file_signature, cuckoo, hwp_status, json_content = parse_json_file(final_report_file)

        # json_content만 있으면 INSERT 수행 (cuckoo=0.0, hwp_status=None 도 허용)
        if json_content is not None:
            insert_email_info(sender, recipient, subject, received_date, spamd, clamav, file_signature, cuckoo, hwp_status, json_content)
        else:
            print(f"Failed to parse JSON file: {final_report_file}", flush=True)
    except Exception as e:
        print(f"Error processing file {final_report_file}: {e}", flush=True)


def process_header_file(file_number):
    header_file = None
    for hdr_file in os.listdir(header_dir):
        if hdr_file.startswith(file_number):
            header_file = os.path.join(header_dir, hdr_file)
            break

    if not header_file or not os.path.exists(header_file):
        print(f"Header 파일이 존재하지 않습니다: {header_file}", flush=True)
        return

    try:
        print(f"Processing header file: {header_file}", flush=True)
        with open(header_file, 'r', encoding='utf-8') as file:
            header = file.read()

        sender, recipient = extract_sender_recipient(header)
        subject = extract_subject(header)
        received_date = extract_received_date(header)

        return sender, recipient, subject, received_date
    except Exception as e:
        print(f"Error processing file {header_file}: {e}", flush=True)
        return None, None, None, None


# ===== 디렉토리 감시 =====
def monitor_dirs(processed_files_set):
    while True:
        all_files = os.listdir(processed_dir)
        for processed_file in all_files:
            if processed_file in processed_files_set:
                continue

            match = re.match(r'^(\d+)\.Vfd01I[a-zA-Z0-9]+M\d+\.mail\.redhat12\.xyz$', processed_file)
            if not match:
                print(f"파일 번호 추출 실패: {processed_file}", flush=True)
                continue

            file_number = match.group(1)
            print(f"Found matching file number: {file_number} for processed file: {processed_file}", flush=True)
            sender, recipient, subject, received_date = process_header_file(file_number)
            if sender and recipient and subject and received_date:
                process_json_file(file_number, sender, recipient, subject, received_date)
                processed_files_set.add(processed_file)
                print(f"Added to processed set: {processed_file}", flush=True)

        time.sleep(1)


# ===== 메인 실행 =====
if __name__ == "__main__":
    processed_files_set = set()

    monitor_thread = threading.Thread(target=monitor_dirs, args=(processed_files_set,))
    monitor_thread.start()

    print("Monitoring directories...", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping directory monitoring...", flush=True)
        monitor_thread.join()

