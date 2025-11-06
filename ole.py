import os
import time
import threading
import olefile
from oletools.olevba import VBA_Parser

def extract_vba_macros(filepath, ole_dir, base_filename):
    try:
        vba_parser = VBA_Parser(filepath)
        if vba_parser.detect_vba_macros():
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_all_macros():
                macro_filename = f"{base_filename}_{vba_filename}"
                macro_path = os.path.join(ole_dir, macro_filename)
                with open(macro_path, 'w') as macro_file:
                    macro_file.write(vba_code)
    except Exception as e:
        print(f"Error extracting VBA macros from {filepath}: {e}")

def extract_ole_objects(filepath):
    try:
        if olefile.isOleFile(filepath):
            ole = olefile.OleFileIO(filepath)
            ole_dir = os.path.join(os.path.dirname(filepath), 'extracted_files', os.path.basename(filepath))
            os.makedirs(ole_dir, exist_ok=True)
            base_filename = os.path.splitext(os.path.basename(filepath))[0]

            for entry in ole.listdir(streams=True, storages=False):
                stream_name = '_'.join(entry)
                stream_path = os.path.join(ole_dir, f"{base_filename}_{stream_name}")

                with open(stream_path, 'wb') as stream_file:
                    stream_file.write(ole.openstream(entry).read())

            extract_vba_macros(filepath, ole_dir, base_filename)

        elif filepath.lower().endswith('.hwp'):
            extract_vba_macros(filepath, ole_dir, base_filename)
        else:
            print(f"Processed file {filepath}")
    except Exception as e:
        print(f"Error extracting OLE objects from {filepath}: {e}")

def analyze_new_file(filepath):
    try:
        if os.path.isfile(filepath):  # Check if it's a file
            extract_ole_objects(filepath)
    except Exception as e:
        print(f"Error analyzing file {filepath}: {e}")

def monitor_dir():
    processed_files = set()

    while True:
        try:
            # Get the list of files in the attachments directory
            for root, _, files in os.walk("/home/goat/Maildir/attachments"):
                for filename in files:
                    filepath = os.path.join(root, filename)

                    # Check for new files
                    if filepath not in processed_files:
                        print("New file detected: {}".format(filepath))
                        analyze_new_file(filepath)
                        processed_files.add(filepath)

            # Wait for 1 second before checking again
            time.sleep(1)
        except Exception as e:
            print(f"Error monitoring directory: {e}")

# Start monitoring directory
monitor_thread = threading.Thread(target=monitor_dir)
monitor_thread.start()

print("Monitoring attachments directory...")

