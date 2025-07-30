import subprocess
import sys
import re
import time
from log_handler import log_error, log_info, log_warning
import sys
import re
from pathlib import Path

def run_command(command_list: list[str], raise_on_error: bool = True) -> str:
    try:
        result = subprocess.run(command_list, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except FileNotFoundError:
        log_error(f"Error: Command not found: {' '.join(command_list)}")
        if raise_on_error:
            sys.exit(2)
        else:
            raise
    except subprocess.CalledProcessError:
        log_error(f"Error: Command execution failed: {' '.join(command_list)}")
        if raise_on_error:
            sys.exit(1)
        else:
            raise
    except KeyboardInterrupt:
        log_error("Operation interrupted by user (Ctrl+C)")
        print("\nOperation interrupted by user (Ctrl+C)")
        sys.exit(130)  # Standard exit code for SIGINT

def run_command_with_progress(command_list: list[str], progress_callback=None, stop_flag=None) -> str:
    """Run command with progress monitoring and cancellation support"""
    try:
        # Start process
        process = subprocess.Popen(command_list, stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE, text=True)
        
        # Monitor progress
        while process.poll() is None:
            if stop_flag and stop_flag():
                # User requested cancellation
                process.terminate()
                process.wait()
                raise KeyboardInterrupt("Operation cancelled by user")
            
            # Update progress if callback provided
            if progress_callback:
                progress_callback()
            
            time.sleep(1)
        
        # Wait for completion and get output
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command_list, stdout, stderr)
        
        return stdout.strip()
        
    except FileNotFoundError:
        log_error(f"Error: Command not found: {' '.join(command_list)}")
        raise
    except subprocess.CalledProcessError as e:
        log_error(f"Error: Command execution failed: {' '.join(command_list)}")
        if e.stderr:
            log_error(f"Error output: {e.stderr}")
        raise
    except KeyboardInterrupt:
        log_error("Operation interrupted by user")
        raise

def get_disk_list() -> list[dict]:
    """
    Get list of available disks as structured data.
    Returns a list of dictionaries with disk information.
    Each dictionary contains: 'device', 'size', and 'model'.
    """
    try:
        # Use more explicit column specification with -o option and -n to skip header
        output = run_command(["lsblk", "-d", "-o", "NAME,SIZE,TYPE,MODEL", "-n"])
        
        if not output:
            # Fallback to a simpler command if the first one returned no results
            output = run_command(["lsblk", "-d", "-o", "NAME", "-n"])
            if not output:
                log_info("No disks detected. Ensure the program is run with appropriate permissions.")
                return []
        
        # Parse the output from lsblk command
        disks = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            # Split the line but preserve the model name which might contain spaces
            parts = line.strip().split(maxsplit=3)
            device = parts[0]
            
            # Ensure we have at least NAME and SIZE
            if len(parts) >= 2:
                size = parts[1]
                
                # MODEL may be missing, set to "Unknown" if it is
                model = parts[3] if len(parts) > 3 else "Unknown"
                
                disks.append({
                    "device": f"/dev/{device}",
                    "size": size,
                    "model": model
                })
        return disks
    except FileNotFoundError as e:
        log_error(f"Error: Command not found: {str(e)}")
        return []
    except subprocess.CalledProcessError as e:
        log_error(f"Error executing command: {str(e)}")
        return []
    except (IndexError, ValueError) as e:
        log_error(f"Error parsing disk information: {str(e)}")
        return []
    except KeyboardInterrupt:
        log_error("Disk listing interrupted by user")
        return []

def get_base_disk(device_name: str) -> str:
    """
    Extract base disk name from a device name.
    Examples: 
        'nvme0n1p1' -> 'nvme0n1'
        'sda1' -> 'sda'
        'nvme0n1' -> 'nvme0n1'
    """
    try:
        # Handle nvme devices (e.g., nvme0n1p1 -> nvme0n1)
        if 'nvme' in device_name:
            match = re.match(r'(nvme\d+n\d+)', device_name)
            if match:
                return match.group(1)
        
        # Handle traditional devices (e.g., sda1 -> sda)
        match = re.match(r'([a-zA-Z/]+[a-zA-Z])', device_name)
        if match:
            return match.group(1)
        
        # If no pattern matches, return the original
        return device_name
        
    except (re.error, AttributeError) as e:
        log_error(f"Regex error processing device name '{device_name}': {str(e)}")
        return device_name
    except TypeError:
        log_error(f"Invalid device name type: expected string, got {type(device_name)}")
        return str(device_name) if device_name is not None else ""
    
def get_active_disk():
    """
    Detect the active device backing the root filesystem.
    Always returns a list of devices or None for consistency.
    Uses LVM logic if the root device is a logical volume (/dev/mapper/),
    otherwise uses regular disk detection logic including live boot media detection.
    """
    try:
        # Initialize devices set for collecting all active devices
        devices = set()
        live_boot_found = False
        
        # Step 1: Check /proc/mounts for all mounted devices
        with open('/proc/mounts', 'r') as f:
            mounts_content = f.read()
            
            # Look for root filesystem mount
            root_device = None
            for line in mounts_content.split('\n'):
                if line.strip() and ' / ' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        root_device = parts[0]
                        break

        # Step 2: Handle special live boot cases where root is not a real device
        if not root_device or root_device in ['rootfs', 'overlay', 'aufs', '/dev/root']:
            
            # In live boot, look for the actual boot media in /proc/mounts
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        device = parts[0]
                        mount_point = parts[1]
                        
                        # Look for common live boot mount points
                        if any(keyword in mount_point for keyword in ['/run/live', '/lib/live', '/live/', '/cdrom']):
                            match = re.search(r'/dev/([a-zA-Z]+\d*[a-zA-Z]*\d*)', device)
                            if match:
                                devices.add(match.group(1))
                                live_boot_found = True
                        
                        # Also check for USB/removable media patterns
                        elif device.startswith('/dev/') and any(keyword in device for keyword in ['sd', 'nvme', 'mmc']):
                            # Check if this looks like a removable device by checking mount point
                            if '/media' in mount_point or '/mnt' in mount_point or '/run' in mount_point:
                                match = re.search(r'/dev/([a-zA-Z]+\d*[a-zA-Z]*\d*)', device)
                                if match:
                                    devices.add(match.group(1))
            
            # If we still haven't found anything, fall back to df command analysis
            if not devices:
                # Use df command instead of viewing /proc/mounts
                try:
                    output = run_command(["df", "-h"])
                    lines = output.strip().split('\n')
                    
                    for line in lines[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 6:
                            device = parts[0]
                            mount_point = parts[5]
                            
                            # Look for any mounted storage devices
                            if device.startswith('/dev/') and any(keyword in device for keyword in ['sd', 'nvme', 'mmc']):
                                match = re.search(r'/dev/([a-zA-Z]+\d*[a-zA-Z]*\d*)', device)
                                if match:
                                    devices.add(match.group(1))
                except (FileNotFoundError, subprocess.CalledProcessError) as e:
                    log_error(f"Error running df command: {str(e)}")
        
        else:
            # Step 3: Handle normal root device (installed system)
            # Check if this is LVM/device mapper
            if '/dev/mapper/' in root_device or '/dev/dm-' in root_device:
                # LVM resolution - simplified without the complex function
                # For the cloner, we'll just mark the base disk as active
                # This is a simplification but should work for most cases
                try:
                    # Use lsblk to find parent devices
                    output = run_command(["lsblk", "-no", "PKNAME", root_device])
                    if output:
                        parent_devices = output.strip().split('\n')
                        for parent in parent_devices:
                            if parent.strip():
                                devices.add(get_base_disk(parent.strip()))
                except (FileNotFoundError, subprocess.CalledProcessError):
                    # Fallback: extract device name from mapper path
                    # This is very basic but better than nothing
                    pass
                    
            else:
                # Regular disk - extract device name with improved regex for NVMe
                match = re.search(r'/dev/([a-zA-Z]+\d*[a-zA-Z]*\d*)', root_device)
                if match:
                    devices.add(match.group(1))
            
            # Also check for live boot media even in normal systems
            try:
                output = run_command(["df", "-h"])
                lines = output.strip().split('\n')
                
                for line in lines[1:]:  # Skip header line
                    parts = line.split()
                    if len(parts) >= 6:
                        device = parts[0]
                        mount_point = parts[5]
                        
                        # Check for live boot mount points
                        if "/run/live" in mount_point or "/lib/live" in mount_point:
                            match = re.search(r'/dev/([a-zA-Z]+\d*[a-zA-Z]*\d*)', device)
                            if match:
                                devices.add(match.group(1))
                                live_boot_found = True
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                pass  # Not critical

        # Step 4: Return logic
        if devices:
            device_list = list(devices)
            
            # If we found live boot devices, prioritize those (remove LVM if present)
            if live_boot_found:
                # Filter out LVM devices when live boot is detected, keep only regular disk names
                final_devices = [dev for dev in device_list if not dev.startswith('/dev/')]
                if final_devices:
                    return final_devices
            return device_list
        else:
            log_error("No active devices found")
            return None

    except FileNotFoundError as e:
        log_error(f"Required file not found: {str(e)}")
        return None
    except PermissionError as e:
        log_error(f"Permission denied accessing system files: {str(e)}")
        return None
    except OSError as e:
        log_error(f"OS error accessing system information: {str(e)}")
        return None
    except subprocess.CalledProcessError as e:
        log_error(f"Error running command: {str(e)}")
        return None
    except (IndexError, ValueError) as e:
        log_error(f"Error parsing command output: {str(e)}")
        return None
    except re.error as e:
        log_error(f"Regex pattern error: {str(e)}")
        return None
    except KeyboardInterrupt:
        log_error("Operation interrupted by user")
        return None
    except UnicodeDecodeError as e:
        log_error(f"Error decoding file content: {str(e)}")
        return None
    except MemoryError:
        log_error("Insufficient memory to process device information")
        return None

def get_disk_serial(device: str) -> str:
    """
    Get a stable disk identifier using udevadm to extract WWN or serial number from an unmounted device.
    """
    try:
        # Try getting the WWN (World Wide Name) directly from udevadm
        output = subprocess.run(
            ["udevadm", "info", "--query=property", f"--name=/dev/{device}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ).stdout.decode()

        # Look for WWN in the udevadm output
        wwn_match = re.search(r'ID_WWN=(\S+)', output)
        if wwn_match:
            return wwn_match.group(1)

        # If WWN not found, fall back to the serial number
        serial_match = re.search(r'ID_SERIAL_SHORT=(\S+)', output)
        if serial_match:
            return serial_match.group(1)
        
        # Get the model as a fallback if serial is not available
        model_match = re.search(r'ID_MODEL=(\S+)', output)
        if model_match:
            return f"{model_match.group(1)}_{device}"
            
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log_error(f"Error occurred while querying {device}: {e}")
    except KeyboardInterrupt:
        log_error("Disk identification interrupted by user (Ctrl+C)")
        print("\nDisk identification interrupted by user (Ctrl+C)")
        sys.exit(130)

    # If all else fails, return a default identifier
    return f"UNKNOWN_{device}"

def is_ssd(device: str) -> bool:
    try:
        output = subprocess.run(
            ["cat", f"/sys/block/{device}/queue/rotational"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return output.stdout.decode().strip() == "0"
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        log_warning(f"SSD check failed for {device}: {e}")
        # Don't exit, just return False as fallback
        return False
    except KeyboardInterrupt:
        log_error("SSD check interrupted by user (Ctrl+C)")
        print("\nSSD check interrupted by user (Ctrl+C)")
        sys.exit(130)