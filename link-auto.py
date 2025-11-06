import email
import os
import re
import threading
import time

# Extract links function
def extract_links(filename, output_dir, processed_files):
    # Check if the file has been processed already
    if filename in processed_files:
        return

    with open(filename, 'rb') as f:
        msg = email.message_from_bytes(f.read())

    links = []
    for part in msg.walk():
        if part.get_content_type() == 'text/plain' or part.get_content_type() == 'text/html':
            content = part.get_payload(decode=True).decode('utf-8')
            # Extract links using regular expressions
            part_links = re.findall(r"(https?://[^\s]+)", content)
            links.extend(part_links)

    # Save extracted links to a file
    if links:
        output_filename = os.path.join(output_dir, os.path.splitext(os.path.basename(filename))[0] + "_links.txt")
        with open(output_filename, 'w') as f:
            for link in links:
                f.write(link + '\n')
        print(f"Links extracted from {filename}: {len(links)}")

    else:
        print(f"No links found in {filename}")

    # Add filename to processed files
    processed_files.add(filename)


def monitor_dir(eml_dir, output_dir, processed_files):
    while True:
        # Check for new files
        for filename in os.listdir(eml_dir):
            if filename.endswith(".xyz") and filename not in processed_files:  # Check if file not processed yet
                email_path = os.path.join(eml_dir, filename)

                # Extract links from new file
                extract_links(email_path, output_dir, processed_files)

        # Wait for 1 second before checking again
        time.sleep(1)


# Main program
if __name__ == "__main__":
    # Set directories
    eml_dir = "/home/goat/Maildir/new"
    output_dir = "/home/goat/Maildir/links"

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Initialize processed files set
    processed_files = set()

    # Start monitoring directory
    monitor_thread = threading.Thread(target=monitor_dir, args=(eml_dir, output_dir, processed_files))
    monitor_thread.start()

    print("Monitoring email directory...")

