import email
import os
import time
import threading

# Extract header function
def extract_header(filename, output_dir):
    # Extract header content
    with open(filename, 'r') as f:
        msg = email.message_from_file(f)
        header_content = msg.as_string()
        boundary_marker = "--" + msg.get_boundary()
        header_content = header_content.split(boundary_marker)[0]

    # Save extracted header
    filename_without_extension = os.path.splitext(os.path.basename(filename))[0]
    output_filename = filename_without_extension + "_header.txt"
    with open(os.path.join(output_dir, output_filename), "w") as output_file:
        output_file.write(header_content)

    print(f"Header extracted from {filename}")

# Monitor email directory
def monitor_dir(eml_dir, output_dir):
    processed_files = set()  # Track processed files
    while True:
        # Check for new files
        for filename in os.listdir(eml_dir):
            if filename.endswith(".xyz") and filename not in processed_files:  # Check if file not processed yet
                email_path = os.path.join(eml_dir, filename)

                # Extract header from new file
                extract_header(email_path, output_dir)

                # Add filename to processed files
                processed_files.add(filename)

        # Wait for 1 second before checking again
        time.sleep(1)

# Main program
if __name__ == "__main__":
    # Set directories
    eml_dir = "/home/roat/Maildir/new"
    output_dir = "/home/goat/Maildir/header"

    # Start monitoring directory
    monitor_thread = threading.Thread(target=monitor_dir, args=(eml_dir, output_dir))
    monitor_thread.start()

    print("Monitoring email directory...")

