# -*- coding: utf-8 -*-

import os
import email
from email.parser import Parser
import MySQLdb
from datetime import datetime
import pytz
from email.header import decode_header
import threading
import time

# MySQL 연결 설정
db = MySQLdb.connect(
    host="localhost",
    user="root",
    passwd="5543",
    db="maildb",
    charset='utf8mb4',
    use_unicode=True
)

cursor = db.cursor()

# 이메일이 저장된 디렉토리 경로
maildir = "/home/goat/Maildir/new"

# 인코딩된 헤더를 디코딩하는 함수
def decode_mime_words(s):
    decoded_words = decode_header(s)
    decoded_string = ''.join([unicode(text, charset or 'utf-8') if isinstance(text, bytes) else text for text, charset in decoded_words])
    return decoded_string

# 메일을 처리하는 함수
def process_email(file_path):
    try:
        with open(file_path, 'r') as f:
            msg = email.message_from_file(f)

            sender = msg['from']
            recipient = msg['to']
            subject = msg['subject']

            # 헤더 디코딩
            if sender:
                sender = decode_mime_words(sender)
            if subject:
                subject = decode_mime_words(subject)

            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        body = part.get_payload(decode=True)
                        break
            else:
                body = msg.get_payload(decode=True)

            # 바이트 문자열을 유니코드로 변환
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='replace')

            received_date = msg['date']

            # 날짜가 없는 경우 건너뛰기
            if received_date is None:
                print("Date not found for email: {}".format(file_path))
                return

            # 날짜 형식 변환
            try:
                received_date = received_date.split(' ')
                received_date_str = ' '.join(received_date[:-1])
                timezone_str = received_date[-1]

                # Python 2는 %z를 지원하지 않으므로 직접 시간대 변환
                naive_dt = datetime.strptime(received_date_str, "%a, %d %b %Y %H:%M:%S")
                offset_hours = int(timezone_str[1:3])
                offset_minutes = int(timezone_str[3:5])
                offset = offset_hours * 3600 + offset_minutes * 60
                if timezone_str[0] == '-':
                    offset = -offset
                local_dt = naive_dt.replace(tzinfo=pytz.FixedOffset(offset / 60))

                # UTC로 변환
                utc_dt = local_dt.astimezone(pytz.utc)
                utc_dt_str = utc_dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                print("Error parsing date for email {}: {}".format(file_path, e))
                return

            # SQL 쿼리 실행
            sql = "INSERT INTO emails (sender, recipient, subject, body, received_date) VALUES (%s, %s, %s, %s, %s)"
            val = (sender, recipient, subject, body, utc_dt_str)
            cursor.execute(sql, val)

            # 데이터베이스 커밋
            db.commit()
    except Exception as e:
        print("Error processing email {}: {}".format(file_path, e))

def monitor_dir(eml_dir, processed_files):
    while True:
        # Check for new files
        for filename in os.listdir(eml_dir):
            if filename not in processed_files:  # Check if file is not processed yet
                email_path = os.path.join(eml_dir, filename)

                # Extract attachments from new file
                process_email(email_path)

                # Add filename to processed files
                processed_files.add(filename)

        # Wait for 1 second before checking again
        time.sleep(1)

if __name__ == "__main__":
    # Initialize processed files set
    processed_files = set()

    # Start monitoring directory
    monitor_thread = threading.Thread(target=monitor_dir, args=(maildir, processed_files))
    monitor_thread.start()

    print("Monitoring email directory...")

    # Ensure the main program continues running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping directory monitoring...")

