import mysql.connector
import csv

# MySQL 데이터베이스 연결
conn = mysql.connector.connect(
    host="localhost",         # MySQL 서버 호스트명
    user="root",     # MySQL 사용자 이름
    password="5543", # MySQL 비밀번호
    database="hexdb"  # 사용할 데이터베이스 이름
)
cursor = conn.cursor()

# CSV 파일 경로
csv_file_path = '/home/goat/CSV/file.csv'

# CSV 파일 데이터를 테이블에 삽입
with open(csv_file_path, mode='r', encoding='utf-8') as file:
    csv_reader = csv.DictReader(file)
    for row in csv_reader:
        cursor.execute("""
            INSERT INTO file_signatures (file_type, header_signature_hex, footer_signature_hex)
            VALUES (%s, %s, %s);
        """, (row['File Type'], row['Header Signature (Hex)'], row['Footer Signature (Hex)']))

# 변경사항 커밋 및 연결 종료
conn.commit()
cursor.close()
conn.close()

