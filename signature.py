import pymysql
import re
import time

# MySQL 데이터베이스에 연결
try:
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password='5543',
        database='maildb'
    )
    print("Database connection successful")
except pymysql.MySQLError as e:
    print(f"Error connecting to database: {e}")
    exit(1)

def extract_file_status(log):
    lines = log.split('\n')
    results = {}

    for line in lines:
        match = re.match(r"File '/home/goat/Maildir/attachments/(.*)' 이 파일은 (.*?)\.", line)
        if match:
            file_path = match.group(1)
            status = match.group(2)
            if status == "안전":
                results[file_path] = "안전"
            elif status == "주의가 필요함":
                results[file_path] = "주의"
    return results

def insert_file_status_info(file_status_results):
    try:
        with connection.cursor() as cursor:
            for file_path, status in file_status_results.items():
                sql = "INSERT INTO result_emails (`File Signature`) VALUES (%s)"
                print(f"Executing SQL: {sql}")  # 디버깅 출력
                print(f"Values: status={status}")  # 디버깅 출력
                cursor.execute(sql, (status,))
        connection.commit()
        print("Inserted file status info into database")
    except pymysql.MySQLError as e:
        print(f"Error: {e}")

def monitor_file(file_path):
    processed_lines = set()

    while True:
        try:
            with open(file_path, 'r') as log_file:
                lines = log_file.readlines()

            new_lines = [line for line in lines if line not in processed_lines]
            if new_lines:
                file_status_results = extract_file_status('\n'.join(new_lines))
                insert_file_status_info(file_status_results)
                processed_lines.update(new_lines)

        except Exception as e:
            print(f"Error reading or processing log file: {e}")

        # 1초 대기 후 다시 확인
        time.sleep(1)

if __name__ == "__main__":
    log_file_path = "/home/goat/Maildir/check_hex.log"
    monitor_file(log_file_path)

