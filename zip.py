import os
import time
import zipfile
import py7zr
from pyunpack import Archive
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ArchiveHandler(FileSystemEventHandler):
    def __init__(self, extract_to):
        self.extract_to = extract_to

    def extract_zip(self, zip_path, extract_to):
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)

    def extract_7z(self, seven_z_path, extract_to):
        with py7zr.SevenZipFile(seven_z_path, mode='r') as z:
            z.extractall(path=extract_to)

    def extract_generic(self, archive_path, extract_to):
        Archive(archive_path).extractall(extract_to)

    def extract_archive(self, archive_path, extract_to):
        if archive_path.endswith('.zip'):
            self.extract_zip(archive_path, extract_to)
        elif archive_path.endswith('.7z'):
            self.extract_7z(archive_path, extract_to)
        else:
            self.extract_generic(archive_path, extract_to)

    def on_created(self, event):
        if event.is_directory:
            return

        archive_path = event.src_path
        if archive_path.endswith(('.zip', '.7z', '.alzip')):
            print(f"New archive found: {archive_path}")
            # Create a directory named after the archive file
            base_name = os.path.basename(archive_path)
            archive_name, archive_ext = os.path.splitext(base_name)
            target_dir = f"{archive_name}_{archive_ext[1:]}"
            unique_extract_to = os.path.join(self.extract_to, target_dir)
            os.makedirs(unique_extract_to, exist_ok=True)
            self.extract_archive(archive_path, unique_extract_to)

            # List extracted files
            extracted_files = os.listdir(unique_extract_to)
            print(f"Extracted files from {archive_path}: {extracted_files}")

def monitor_directory(path, extract_to):
    event_handler = ArchiveHandler(extract_to)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    print(f"Monitoring directory: {path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Example usage
monitor_directory('/home/goat/Maildir/attachments', '/home/goat/Maildir/zipfile')

