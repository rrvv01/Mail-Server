import email
import os
import chardet
import io
import threading
import time

# Extract body function
def extract_body(filename, output_dir, processed_files):
    # Check if the file has been processed already
    if filename in processed_files:
        return

    # Open email file
    with open(filename, 'r') as f:
        msg = email.message_from_file(f)

    # Find boundary marker
    boundary_marker = "--" + msg.get_boundary()

    # Extract body content (text part after header)
    if boundary_marker:
        # Iterate through all parts to find the body part
        for part in msg.walk():
            content_type = part.get_content_maintype()
            if content_type == "text":
                # Decode and save body content
                payload = part.get_payload(decode=True)
                encoding = chardet.detect(payload)["encoding"]
                if encoding:
                    body_content = payload.decode(encoding)
                else:
                    body_content = payload.decode('utf-8')  # Use default if encoding detection fails
                break  # Extract only the first body part (multiple parts possible)
    else:
        # Treat entire message content as body
        payload = msg.get_payload(decode=True)
        encoding = chardet.detect(payload)["encoding"]
        if encoding:
            body_content = payload.decode(encoding)
        else:
            body_content = payload.decode('utf-8')  # Use default if encoding detection fails

    # Save extracted body content
    filename_without_extension = os.path.splitext(os.path.basename(filename))[0]
    output_filename = filename_without_extension + "_body.txt"
    with io.open(os.path.join(output_dir, output_filename), "w", encoding='utf-8') as output_file:
        output_file.write(body_content)

    # Mark the file as processed
    processed_files.add(filename)
    print(f"Body extracted from {filename}")

# Monitor email directory
def monitor_dir(eml_dir, output_dir):
    processed_files = set()  # Store the filenames that have been processed
    while True:
        # Check for new files
        for filename in os.listdir(eml_dir):
            if filename.endswith(".xyz"):
                email_path = os.path.join(eml_dir, filename)

                # Extract body from new file
                extract_body(email_path, output_dir, processed_files)

        # Wait for 1 second before checking again
        time.sleep(1)

# Main program
if __name__ == "__main__":
    # Set directories
    eml_dir = "/home/roat/Maildir/new"
    output_dir = "/home/goat/Maildir/body"

    # Start monitoring directory
    monitor_thread = threading.Thread(target=monitor_dir, args=(eml_dir, output_dir))
    monitor_thread.start()

    print("Monitoring email directory...")

