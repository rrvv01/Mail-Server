# -*- coding: utf-8 -*-

import os
import smtplib
import time
from email.parser import Parser

# 포워딩할 이메일 주소
forward_address = "roat@goat.pe.kr"

# 이메일을 읽을 디렉토리
mail_directory = "/home/goat/Maildir/clean"
processed_files = set()

# 이메일을 포워딩하는 함수
def forward_message(message):
    # 포워딩할 이메일 설정
    forward_to = [forward_address]
    forward_from = message['From']
    
    print("Attempting to forward email from {} to {}".format(forward_from, forward_to))

    # SMTP 서버 연결 (최종 수신지 goat.pe.kr IP)
    smtp_server = smtplib.SMTP('mail.goat.pe.kr')

    try:
        # 이메일 전송
        smtp_server.sendmail(forward_from, forward_to, message.as_string())
        print("Email forwarded from {} to {}".format(forward_from, forward_to))
    except Exception as e:
        print("Failed to forward email: {}".format(e))
    finally:
        # SMTP 연결 종료
        smtp_server.quit()

# 이메일을 읽고 포워딩하는 함수
def forward_emails(filepath):
    print("Processing file: {}".format(filepath))
    try:
        # 이메일 파일 열기
        with open(filepath, "r") as f:
            # 이메일 파싱
            message = Parser().parse(f)
            print("Parsed email from file: {}".format(filepath))

            # 이메일 포워딩
            forward_message(message)

            # 이메일 파일 삭제 (선택 사항)
            # os.remove(filepath)
    except Exception as e:
        print("Failed to process email: {}".format(e))

# 주기적으로 디렉토리를 확인하여 새로운 파일 처리
def monitor_directory():
    while True:
        all_files = os.listdir(mail_directory)
        for filename in all_files:
            if filename not in processed_files:
                processed_files.add(filename)
                filepath = os.path.join(mail_directory, filename)
                forward_emails(filepath)
        time.sleep(10)  # 10초마다 디렉토리 확인

if __name__ == "__main__":
    print("Monitoring directory for new emails...")
    monitor_directory()

