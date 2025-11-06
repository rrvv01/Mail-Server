import os
import time
import threading
import requests
import json

def process_link_files(output_dir, processed_files, result_dir, server_url, timeout):
    for filename in os.listdir(output_dir):
        file_path = os.path.join(output_dir, filename)
        if os.path.isfile(file_path) and filename.endswith('.txt') and filename not in processed_files:
            with open(file_path, 'r') as file:
                body = file.read()

            # Flask 서버로 본문 전송
            try:
                print(f'Sending request for {filename}')
                response = requests.post(server_url, data={'url': body}, timeout=timeout)
                response.raise_for_status()
                print(f'Received response status: {response.status_code}')
                print(f'Received response content: {response.content}')

                # 응답이 JSON 형식인지 확인
                try:
                    result = response.json().get('result')
                    result_str = json.dumps(result, indent=4)
                except ValueError:
                    print(f'Response is not JSON for {filename}: {response.text}')
                    result_str = 'Error'
            except requests.exceptions.Timeout:
                print(f'Timeout occurred for {filename}')
                result_str = 'Error: Timeout'
            except requests.exceptions.RequestException as e:
                print(f'Error processing {filename}: {e}')
                result_str = 'Error'

            # 결과를 지정된 디렉토리에 저장
            result_file_path = os.path.join(result_dir, f'result_{filename}')
            with open(result_file_path, 'w') as result_file:
                result_file.write(result_str)

            print(f'Processed {filename}: {result_str}')
            processed_files.add(filename)

def monitor_dir(output_dir, processed_files, result_dir, server_url, timeout):
    while True:
        process_link_files(output_dir, processed_files, result_dir, server_url, timeout)
        time.sleep(1)

# Main program
if __name__ == "__main__":
    # Set directories
    output_dir = "/home/goat/Maildir/links"
    result_dir = "/home/goat/Maildir/result_ml"
    server_url = 'http://175.194.34.49:65000/predict'
    timeout = 10

    # Ensure the directories exist
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(result_dir, exist_ok=True)

    # Initialize processed files set
    processed_files = set()

    # Start monitoring directory
    monitor_thread = threading.Thread(target=monitor_dir, args=(output_dir, processed_files, result_dir, server_url, timeout))
    monitor_thread.start()

    print("Monitoring links directory...")

