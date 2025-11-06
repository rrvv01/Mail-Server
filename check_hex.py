import mysql.connector
import os
import time
import threading

def get_file_signatures_from_db():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="5543",
            database="hexdb"
        )
        cursor = conn.cursor()
        cursor.execute("SELECT file_type, header_signature_hex, footer_signature_hex FROM file_signatures")
        signatures = cursor.fetchall()
        cursor.close()
        conn.close()
        return signatures
    except Exception as e:
        print(f"Error accessing database: {e}")
        return []

def read_file_signature(file_path, num_bytes, from_end=False):
    try:
        with open(file_path, 'rb') as file:
            if from_end:
                file.seek(-num_bytes, 2)
            return file.read(num_bytes)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return b''

def is_file_malicious(file_path):
    signatures = get_file_signatures_from_db()
    if not signatures:
        return True

    header = read_file_signature(file_path, 8)
    footer = read_file_signature(file_path, 30, from_end=True)  # 끝에서 30 바이트를 읽음.

    header_hex = ' '.join(f'{byte:02X}' for byte in header)
    footer_hex = ' '.join(f'{byte:02X}' for byte in footer)

    print(f"File header signature: {header_hex}")
    print(f"File footer signature: {footer_hex}")

    is_malicious = True  # 초기화

    for file_type, header_signature_hex, footer_signature_hex in signatures:
        header_signature = bytes.fromhex(header_signature_hex.replace(" ", ""))
        footer_signature = bytes.fromhex(footer_signature_hex.replace(" ", ""))

        print(f"Checking against {file_type} signature:")
        print(f"Expected header: {header_signature_hex}")
        print(f"Expected footer: {footer_signature_hex}")

        if header.startswith(header_signature):
            if footer_signature in footer:
                print(f"File '{file_path}' matches '{file_type}' signature.")
                is_malicious = False
                break

    if is_malicious:
        print(f"File '{file_path}' does not match any known signatures and might be malicious.")

    log_filename = os.path.join("/home/goat/Maildir/check_hex.log")
    try:
        with open(log_filename, "a") as log_file:
            if is_malicious:
                result_message = f"Dangerous.\n"
            else:
                result_message = f"File '{file_path}' Safe.\n"

            result_message += f"File header signature: {header_hex}\n"
            result_message += f"File footer signature: {footer_hex}\n"

            result_message += f"Checking against {file_type} signature:\n"
            result_message += f"Expected header: {header_signature_hex}\n"
            result_message += f"Expected footer: {footer_signature_hex}\n"

            print(result_message.strip())
            log_file.write(result_message)
    except Exception as e:
        print(f"Error writing to log file: {e}")

    return is_malicious

def monitor_dirs(directories):
    # Initialize a set to store previously seen filenames
    previous_files = set()
    for directory in directories:
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                previous_files.add(filepath)

    while True:
        for directory in directories:
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath) and filepath not in previous_files:
                    print("New file detected: {}".format(filepath))
                    is_file_malicious(filepath)
                    previous_files.add(filepath)

        # Wait for 1 second before checking again
        time.sleep(1)

# Set directories to monitor
directories_to_monitor = [
    "/home/goat/Maildir/attachments",
]

# Start monitoring directories
monitor_thread = threading.Thread(target=monitor_dirs, args=(directories_to_monitor,))
monitor_thread.start()

print("Monitoring attachments directories...")

