#!/usr/bin/env python3
"""
ClamAV Database Offline Updater for Bootable USB
================================================

This script downloads the latest ClamAV virus database files and installs them
directly on the bootable USB. Run this script from the bootable USB root directory
on a computer with internet connection.

Usage:
    # From the USB root directory:
    python3 update_clamav_db.py
    
    # Or specify a different target directory:
    python3 update_clamav_db.py /path/to/usb/root
"""

import os
import sys
import urllib.request
import urllib.error
import tempfile
import shutil
import hashlib
import time
from pathlib import Path

# ClamAV database URLs
CLAMAV_DB_URLS = {
    'main.cvd': 'https://database.clamav.net/main.cvd',
    'daily.cld': 'https://database.clamav.net/daily.cld', 
    'bytecode.cld': 'https://database.clamav.net/bytecode.cld'
}

# Alternative mirrors
MIRROR_URLS = [
    'https://database.clamav.net/',
    'https://db.local.clamav.net/',
    'https://db.us.clamav.net/',
    'https://db.eu.clamav.net/'
]

class ClamAVUpdater:
    def __init__(self):
        self.temp_dir = None
        self.usb_root_dir = None
        self.db_target_dir = None
        
    def log(self, message, level="INFO"):
        """Simple logging function"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    def detect_usb_root(self, specified_path=None):
        """Detect if we're running from a bootable USB root or find it"""
        if specified_path:
            self.log(f"Using specified USB root: {specified_path}")
            if self.validate_usb_root(specified_path):
                return specified_path
            else:
                raise Exception(f"Specified path is not a valid bootable USB root: {specified_path}")
        
        # Check if current directory looks like our bootable USB root
        current_dir = os.getcwd()
        self.log(f"Checking current directory: {current_dir}")
        
        if self.validate_usb_root(current_dir):
            self.log("Found bootable USB root in current directory")
            return current_dir
        
        # Check parent directory (in case we're in a subdirectory)
        parent_dir = os.path.dirname(current_dir)
        if self.validate_usb_root(parent_dir):
            self.log(f"Found bootable USB root in parent directory: {parent_dir}")
            return parent_dir
        
        # Try to find it in common mount points
        self.log("Searching for bootable USB in common mount points...")
        return self.find_usb_in_mounts()
    
    def validate_usb_root(self, path):
        """Validate if a path looks like our bootable USB root"""
        if not os.path.exists(path):
            return False
        
        # Look for signature files/directories that indicate this is our bootable USB
        signature_items = [
            'var/lib/clamav',  # ClamAV database directory
            'usr/local/bin/main.py',  # Our main scanner script
            'etc/clamav',  # ClamAV config directory
            'update_clamav_db.py'  # This script itself
        ]
        
        found_signatures = 0
        for item in signature_items:
            item_path = os.path.join(path, item)
            if os.path.exists(item_path):
                found_signatures += 1
                self.log(f"Found signature: {item}")
        
        # We need at least 2 signature items to be confident
        return found_signatures >= 2
    
    def find_usb_in_mounts(self):
        """Search for bootable USB in common mount points"""
        possible_mounts = [
            '/media',
            '/mnt',
            '/run/media',
            '/Volumes'  # macOS
        ]
        
        for base_path in possible_mounts:
            if not os.path.exists(base_path):
                continue
                
            try:
                for item in os.listdir(base_path):
                    mount_path = os.path.join(base_path, item)
                    if not os.path.isdir(mount_path):
                        continue
                    
                    if self.validate_usb_root(mount_path):
                        self.log(f"Found bootable USB at: {mount_path}")
                        return mount_path
            except PermissionError:
                continue
        
        return None
    
    def setup_directories(self, usb_root):
        """Setup the required directories"""
        self.usb_root_dir = usb_root
        
        # Target directory for ClamAV database in the USB
        self.db_target_dir = os.path.join(usb_root, 'var', 'lib', 'clamav')
        
        # Create target directory if it doesn't exist
        os.makedirs(self.db_target_dir, exist_ok=True)
        self.log(f"Database target directory: {self.db_target_dir}")
        
        # Create temporary directory for downloads
        self.temp_dir = tempfile.mkdtemp(prefix='clamav_update_')
        self.log(f"Using temporary directory: {self.temp_dir}")
        
        return True
    
    def download_file(self, url, filename, max_retries=3):
        """Download a file with progress indication and retry logic"""
        temp_file = os.path.join(self.temp_dir, filename)
        
        for attempt in range(max_retries):
            try:
                self.log(f"Downloading {filename} (attempt {attempt + 1}/{max_retries})...")
                
                # Create request with user agent
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'ClamAV-Update-Script/1.0')
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    total_size = int(response.headers.get('Content-Length', 0))
                    
                    with open(temp_file, 'wb') as f:
                        downloaded = 0
                        chunk_size = 8192
                        
                        while True:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                print(f"\rProgress: {progress:.1f%} ({downloaded}/{total_size} bytes)", end='')
                            else:
                                print(f"\rDownloaded: {downloaded} bytes", end='')
                
                print()  # New line after progress
                self.log(f"Successfully downloaded {filename}")
                return temp_file
                
            except urllib.error.URLError as e:
                self.log(f"Download failed for {filename}: {str(e)}", "ERROR")
                if attempt < max_retries - 1:
                    self.log(f"Retrying in 5 seconds...", "WARNING")
                    time.sleep(5)
                else:
                    raise
            except Exception as e:
                self.log(f"Unexpected error downloading {filename}: {str(e)}", "ERROR")
                if attempt < max_retries - 1:
                    time.sleep(5)
                else:
                    raise
        
        return None
    
    def verify_file(self, filepath):
        """Basic file verification"""
        if not os.path.exists(filepath):
            return False
        
        # Check if file is not empty
        if os.path.getsize(filepath) == 0:
            return False
        
        # For .cvd and .cld files, check if they start with the ClamAV signature
        try:
            with open(filepath, 'rb') as f:
                header = f.read(12)  # Read more bytes for better detection
                if header.startswith(b'ClamAV-VDB'):
                    return True
        except Exception:
            pass
        
        # If header check fails, still accept if file size is reasonable
        file_size = os.path.getsize(filepath)
        return file_size > 1000  # At least 1KB
    
    def backup_existing_db(self):
        """Backup existing database files"""
        backup_dir = os.path.join(self.db_target_dir, 'backup')
        
        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir)
        
        os.makedirs(backup_dir, exist_ok=True)
        
        backed_up = 0
        for db_file in CLAMAV_DB_URLS.keys():
            existing_file = os.path.join(self.db_target_dir, db_file)
            if os.path.exists(existing_file):
                backup_file = os.path.join(backup_dir, db_file)
                shutil.copy2(existing_file, backup_file)
                self.log(f"Backed up {db_file}")
                backed_up += 1
        
        if backed_up == 0:
            self.log("No existing database files to backup")
        else:
            self.log(f"Backed up {backed_up} existing database files")
    
    def install_database_files(self):
        """Install downloaded database files"""
        self.log("Installing database files...")
        
        installed_files = []
        
        for db_file in CLAMAV_DB_URLS.keys():
            temp_file = os.path.join(self.temp_dir, db_file)
            target_file = os.path.join(self.db_target_dir, db_file)
            
            if os.path.exists(temp_file):
                if self.verify_file(temp_file):
                    try:
                        shutil.copy2(temp_file, target_file)
                        # Set appropriate permissions
                        os.chmod(target_file, 0o644)
                        installed_files.append(db_file)
                        
                        # Log file size for verification
                        file_size = os.path.getsize(target_file)
                        self.log(f"Installed {db_file} ({file_size} bytes)")
                    except Exception as e:
                        self.log(f"Failed to install {db_file}: {str(e)}", "ERROR")
                else:
                    self.log(f"Verification failed for {db_file}", "ERROR")
            else:
                self.log(f"Downloaded file not found: {db_file}", "ERROR")
        
        return installed_files
    
    def create_update_info(self):
        """Create a file with update information"""
        info_file = os.path.join(self.db_target_dir, 'update_info.txt')
        
        try:
            with open(info_file, 'w') as f:
                f.write(f"ClamAV Database Update Information\n")
                f.write(f"==================================\n\n")
                f.write(f"Update Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Updated by: Offline Database Updater Script\n")
                f.write(f"USB Root Directory: {self.usb_root_dir}\n\n")
                
                f.write("Database Files:\n")
                for db_file in CLAMAV_DB_URLS.keys():
                    file_path = os.path.join(self.db_target_dir, db_file)
                    if os.path.exists(file_path):
                        size = os.path.getsize(file_path)
                        mtime = time.strftime('%Y-%m-%d %H:%M:%S', 
                                            time.localtime(os.path.getmtime(file_path)))
                        f.write(f"  {db_file}: {size} bytes (modified: {mtime})\n")
                    else:
                        f.write(f"  {db_file}: MISSING\n")
            
            self.log(f"Created update info file: {info_file}")
        except Exception as e:
            self.log(f"Failed to create update info file: {str(e)}", "ERROR")
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                self.log("Cleaned up temporary files")
            except Exception as e:
                self.log(f"Failed to cleanup temporary files: {str(e)}", "WARNING")
    
    def check_internet_connection(self):
        """Check if we have internet connectivity"""
        try:
            self.log("Checking internet connectivity...")
            urllib.request.urlopen('https://database.clamav.net/', timeout=10)
            self.log("Internet connection confirmed")
            return True
        except Exception as e:
            self.log(f"No internet connection: {str(e)}", "ERROR")
            return False
    
    def update_database(self, usb_root_path=None):
        """Main update function"""
        try:
            # Check internet connection first
            if not self.check_internet_connection():
                raise Exception("No internet connection available. Please connect to the internet and try again.")
            
            # Find USB root directory
            usb_root = self.detect_usb_root(usb_root_path)
            if not usb_root:
                raise Exception("Could not find bootable USB root directory.\n"
                               "Please run this script from the USB root directory or specify the path.")
            
            # Setup directories
            if not self.setup_directories(usb_root):
                raise Exception("Failed to setup directories")
            
            self.log(f"USB root directory: {self.usb_root_dir}")
            self.log(f"Target database directory: {self.db_target_dir}")
            
            # Check if target directory is writable
            if not os.access(self.db_target_dir, os.W_OK):
                raise Exception(f"No write permission to database directory: {self.db_target_dir}")
            
            # Backup existing database
            self.backup_existing_db()
            
            # Download database files
            success_count = 0
            for db_file, url in CLAMAV_DB_URLS.items():
                try:
                    downloaded_file = self.download_file(url, db_file)
                    if downloaded_file:
                        success_count += 1
                except Exception as e:
                    self.log(f"Failed to download {db_file}: {str(e)}", "ERROR")
                    # Try alternative mirrors
                    for mirror in MIRROR_URLS[1:]:  # Skip first one (already tried)
                        try:
                            alt_url = mirror + db_file
                            self.log(f"Trying alternative mirror: {alt_url}")
                            downloaded_file = self.download_file(alt_url, db_file)
                            if downloaded_file:
                                success_count += 1
                                break
                        except Exception as mirror_e:
                            self.log(f"Mirror {mirror} failed: {str(mirror_e)}", "WARNING")
                            continue
            
            if success_count == 0:
                raise Exception("Failed to download any database files")
            
            # Install database files
            installed_files = self.install_database_files()
            
            if not installed_files:
                raise Exception("No database files were successfully installed")
            
            # Create update info
            self.create_update_info()
            
            self.log(f"Database update completed successfully!")
            self.log(f"Updated files: {', '.join(installed_files)}")
            self.log(f"Database location: {self.db_target_dir}")
            
            return True
            
        except Exception as e:
            self.log(f"Update failed: {str(e)}", "ERROR")
            return False
        
        finally:
            self.cleanup()

def main():
    """Main function"""
    print("ClamAV Database Offline Updater for Bootable USB")
    print("=" * 50)
    print()
    print("This script will update the ClamAV virus database on the bootable USB.")
    print("Make sure you have internet connection and run from the USB root directory.")
    print()
    
    # Check for command line argument
    usb_root_path = None
    if len(sys.argv) > 1:
        usb_root_path = sys.argv[1]
        print(f"Using specified USB root path: {usb_root_path}")
    else:
        print("Auto-detecting USB root directory...")
    
    print()
    
    # Create updater and run
    updater = ClamAVUpdater()
    success = updater.update_database(usb_root_path)
    
    print()
    if success:
        print("✅ Database update completed successfully!")
        print()
        print("The bootable USB now has the latest ClamAV virus definitions.")
        print("You can now boot from this USB and perform virus scans with updated definitions.")
        print()
        print("Next steps:")
        print("1. Safely eject the USB from this computer")
        print("2. Boot the target computer from this USB")
        print("3. Use the virus scanner with updated database")
    else:
        print("❌ Database update failed!")
        print()
        print("Please check the error messages above and try again.")
        print("Common issues:")
        print("- No internet connection")
        print("- USB not mounted or not writable") 
        print("- Not running from the correct USB root directory")
        print()
        print("Make sure to run this script from the bootable USB root directory.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())