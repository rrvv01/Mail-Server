import os
import subprocess
import threading
import time

def analyze_new_file(filepath):
    # Check if file exists before scanning
    if not os.path.exists(filepath):
        print(f"File does not exist: {filepath}")
        return

    # Run ClamAV scan on the new file
    process = subprocess.Popen(["clamscan", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    # Log scan command and results for debugging
    print(f"Running command: clamscan {filepath}")
    print(f"stdout: {stdout.decode('utf-8')}")
    print(f"stderr: {stderr.decode('utf-8')}")

    # Check the scan result and save it to a log file
    log_filename = os.path.join("/home/goat/Maildir/scan_results.log")
    with open(log_filename, "a") as log_file:
        if process.returncode == 0:
            result_message = "File '{}' scanned clean.\n".format(filepath)
        else:
            result_message = "File '{}' contains virus/malware:\n{}\n".format(
                filepath, stdout.decode('utf-8'))

        # Print the result to the console
        print(result_message.strip())

        # Write the result to the log file
        log_file.write(result_message)

def monitor_dirs(directories):
    # Initialize a set to store previously seen filenames
    previous_files = {filepath for directory in directories for root, _, files in os.walk(directory) for filepath in (os.path.join(root, file) for file in files)}

    while True:
        for directory in directories:
            # Get the list of files in the directory
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)

                    # Check for new files
                    if filepath not in previous_files:
                        print("New file detected: {}".format(filepath))
                        analyze_new_file(filepath)
                        previous_files.add(filepath)

        # Wait for 1 second before checking again
        time.sleep(1)

# Set directories to monitor
directories_to_monitor = [
    "/home/goat/Maildir/attachments",
    "/home/goat/Maildir/attachments/extracted_files",
    "/home/goat/Maildir/zipfile"
]

# Start monitoring directories
monitor_thread = threading.Thread(target=monitor_dirs, args=(directories_to_monitor,))
monitor_thread.start()

print("Monitoring attachments, extracted_files, and zipfile directories...")

