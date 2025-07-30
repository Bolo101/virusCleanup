#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, List, Set
from subprocess import CalledProcessError, TimeoutExpired

# Import functions from existing modules
from utils import get_disk_list, get_base_disk, get_active_disk, get_disk_serial, is_ssd, run_command, run_command_with_progress
from log_handler import log_info, log_error, log_warning

class VirusScannerGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Disk Virus Scanner")
        self.root.geometry("800x700")
        # Set fullscreen mode
        self.root.attributes("-fullscreen", True)
        
        # Variables for disk selection
        self.selected_disk_var = tk.StringVar()
        self.scan_mode_var = tk.StringVar(value="quick")  # Changed default to quick
        self.quarantine_var = tk.BooleanVar(value=False)
        self.remove_infected_var = tk.BooleanVar(value=False)
        
        # Data storage
        self.disks: List[Dict[str, str]] = []
        self.active_disks: Set[str] = set()
        self.is_scanning = False
        self.scan_results = {
            'scanned': 0,
            'infected': 0,
            'threats': []
        }
        
        # Check for root privileges
        if os.geteuid() != 0:
            messagebox.showerror("Error", "This program must be run as root!")
            root.destroy()
            sys.exit(1)
        
        # Check if ClamAV is installed
        if not self.check_clamav_installed():
            messagebox.showerror("Error", 
                               "ClamAV is not installed!\n\n"
                               "Please install it using:\n"
                               "sudo apt-get install clamav clamav-daemon\n"
                               "or equivalent for your distribution.")
            root.destroy()
            sys.exit(1)
        
        self.create_widgets()
        self.refresh_disks()
        self.check_database_status()
    
    def check_clamav_installed(self) -> bool:
        """Check if ClamAV is installed on the system"""
        try:
            run_command(["which", "clamscan"], raise_on_error=False)
            return True
        except (CalledProcessError, FileNotFoundError):
            return False
    
    def check_database_status(self) -> None:
        """Check ClamAV database status and display information with popup"""
        db_status = self.get_database_info()
        self.update_log(f"ClamAV Database Status: {db_status['status']}")
        
        if db_status['files']:
            self.update_log("Available database files:")
            for db_file, info in db_status['files'].items():
                self.update_log(f"  {db_file}: {info}")
        
        if db_status['last_update']:
            self.update_log(f"Last update: {db_status['last_update']}")
        
        # Show database status in GUI
        if db_status['status'] == "OK":
            self.db_status_var.set("✅ Virus database: Ready")
        elif db_status['status'] == "OUTDATED":
            self.db_status_var.set("⚠️ Virus database: Available but may be outdated")
        else:
            self.db_status_var.set("❌ Virus database: Missing or incomplete")
        
        # Show the database info popup
        self.show_database_info()
    
    def get_database_info(self) -> Dict:
        """Get information about ClamAV database files"""
        db_dir = "/var/lib/clamav"
        db_files = ["main.cvd", "main.cld", "daily.cvd", "daily.cld", "bytecode.cvd", "bytecode.cld"]
        
        result = {
            'status': 'MISSING',
            'files': {},
            'last_update': None
        }
        
        found_files = 0
        newest_time = 0
        
        for db_file in db_files:
            file_path = os.path.join(db_dir, db_file)
            if os.path.exists(file_path):
                try:
                    stat = os.stat(file_path)
                    size = stat.st_size
                    mtime = stat.st_mtime
                    
                    if mtime > newest_time:
                        newest_time = mtime
                    
                    # Format file info
                    size_mb = size / (1024 * 1024)
                    mod_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
                    result['files'][db_file] = f"{size_mb:.1f}MB (modified: {mod_time})"
                    found_files += 1
                    
                except OSError:
                    continue
        
        # Check for update info file
        update_info_file = os.path.join(db_dir, "update_info.txt")
        if os.path.exists(update_info_file):
            try:
                with open(update_info_file, 'r') as f:
                    content = f.read()
                    # Extract update date from the file
                    for line in content.split('\n'):
                        if 'Update Date:' in line:
                            result['last_update'] = line.split('Update Date:')[1].strip()
                            break
            except Exception:
                pass
        
        # Determine status
        if found_files >= 2:  # At least main and daily databases
            if newest_time > 0:
                days_old = (time.time() - newest_time) / (24 * 3600)
                if days_old < 7:
                    result['status'] = 'OK'
                else:
                    result['status'] = 'OUTDATED'
            else:
                result['status'] = 'OK'
        
        if not result['last_update'] and newest_time > 0:
            result['last_update'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(newest_time))
        
        return result
    
    def get_disk_partitions(self, device: str) -> List[str]:
        """Get list of partitions for a given disk device"""
        try:
            # Remove /dev/ prefix if present
            base_device = device.replace('/dev/', '')
            
            # Use lsblk to get partitions
            output = run_command(["lsblk", "-no", "NAME", f"/dev/{base_device}"])
            
            partitions = []
            lines = output.strip().split('\n')
            
            for line in lines[1:]:  # Skip the first line (the disk itself)
                partition = line.strip()
                if partition.startswith('├─') or partition.startswith('└─'):
                    # Remove tree characters
                    partition = partition.replace('├─', '').replace('└─', '').strip()
                elif partition.startswith('  '):
                    # Handle different tree formatting
                    partition = partition.strip()
                
                if partition and partition != base_device:
                    partitions.append(f"/dev/{partition}")
            
            return partitions
            
        except Exception as e:
            log_warning(f"Error getting partitions for {device}: {str(e)}")
            return []
    
    def create_widgets(self) -> None:
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Disk Virus Scanner", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # Database status frame
        db_frame = ttk.Frame(main_frame)
        db_frame.pack(fill=tk.X, pady=5)
        
        self.db_status_var = tk.StringVar(value="Checking virus database...")
        db_status_label = ttk.Label(db_frame, textvariable=self.db_status_var, font=("Arial", 10))
        db_status_label.pack(side=tk.LEFT)
        
        # Disk selection frame
        selection_frame = ttk.LabelFrame(main_frame, text="Select Disk to Scan")
        selection_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Disk listbox with scrollbar
        disk_list_frame = ttk.Frame(selection_frame)
        disk_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.disk_listbox = tk.Listbox(disk_list_frame, selectmode=tk.SINGLE, height=8)
        disk_scrollbar = ttk.Scrollbar(disk_list_frame, orient=tk.VERTICAL, command=self.disk_listbox.yview)
        self.disk_listbox.configure(yscrollcommand=disk_scrollbar.set)
        self.disk_listbox.bind('<<ListboxSelect>>', self.on_disk_select)
        
        self.disk_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        disk_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Disk info
        self.disk_info_var = tk.StringVar(value="No disk selected")
        disk_info_label = ttk.Label(selection_frame, textvariable=self.disk_info_var, 
                                   wraplength=600, justify=tk.LEFT)
        disk_info_label.pack(pady=5)
        
        # Warning labels
        self.disk_warning_var = tk.StringVar()
        disk_warning_label = ttk.Label(selection_frame, textvariable=self.disk_warning_var, 
                                      foreground="red", wraplength=600)
        disk_warning_label.pack(pady=2)
        
        # Scan options frame
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options")
        options_frame.pack(fill=tk.X, pady=10)
        
        # Scan mode options
        mode_frame = ttk.Frame(options_frame)
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(mode_frame, text="Scan Mode:").pack(side=tk.LEFT, padx=5)
        
        ttk.Radiobutton(mode_frame, text="Quick Scan (mounted partitions only)", 
                       value="quick", variable=self.scan_mode_var).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(mode_frame, text="Deep Scan (all partitions)", 
                       value="deep", variable=self.scan_mode_var).pack(side=tk.LEFT, padx=10)
        
        # Action options
        action_frame2 = ttk.Frame(options_frame)
        action_frame2.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Checkbutton(action_frame2, text="Remove infected files (DANGER!)", 
                       variable=self.remove_infected_var).pack(side=tk.LEFT, padx=5)
        
        # Database update info
        info_frame = ttk.Frame(options_frame)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text="💡 To update virus database: Use update_clamav_db.py script from the USB root directory", 
                 foreground="blue", wraplength=600).pack(side=tk.LEFT)
        
        # Control buttons frame
        control_frame = ttk.Frame(options_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Refresh button
        ttk.Button(control_frame, text="Refresh Disks", 
                  command=self.refresh_disks).pack(side=tk.LEFT, padx=5)
        
        # Refresh database status button (now shows popup)
        ttk.Button(control_frame, text="Refresh DB Status", 
                  command=self.check_database_status).pack(side=tk.LEFT, padx=5)
        
        # Start scan button
        self.start_button = ttk.Button(control_frame, text="Start Scan", 
                                      command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # Stop scan button
        self.stop_button = ttk.Button(control_frame, text="Stop Scan", 
                                     command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Exit fullscreen button
        ttk.Button(control_frame, text="Exit Fullscreen", 
                  command=self.toggle_fullscreen).pack(side=tk.RIGHT, padx=5)
        
        # Exit button
        ttk.Button(control_frame, text="Exit", 
                  command=self.exit_application).pack(side=tk.RIGHT, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Scan Progress")
        progress_frame.pack(fill=tk.X, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                       maximum=100, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(progress_frame, textvariable=self.status_var)
        status_label.pack(pady=5)
        
        # Scan results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results")
        results_frame.pack(fill=tk.X, pady=5)
        
        results_info_frame = ttk.Frame(results_frame)
        results_info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.scanned_var = tk.StringVar(value="Files scanned: 0")
        ttk.Label(results_info_frame, textvariable=self.scanned_var).pack(side=tk.LEFT, padx=10)
        
        self.infected_var = tk.StringVar(value="Threats found: 0")
        infected_label = ttk.Label(results_info_frame, textvariable=self.infected_var, foreground="red")
        infected_label.pack(side=tk.LEFT, padx=10)
        
        # Log frame (increased height)
        log_frame = ttk.LabelFrame(main_frame, text="Scan Log")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.log_text = tk.Text(log_frame, height=15, wrap=tk.WORD)  # Increased from 10 to 15
        log_scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Window close protocol
        self.root.protocol("WM_DELETE_WINDOW", self.exit_application)
    
    def show_database_info(self) -> None:
        """Show detailed database information"""
        db_info = self.get_database_info()
        
        info_text = f"ClamAV Database Information\n{'='*40}\n\n"
        info_text += f"Status: {db_info['status']}\n"
        
        if db_info['last_update']:
            info_text += f"Last Update: {db_info['last_update']}\n"
        
        info_text += "\nDatabase Files:\n"
        if db_info['files']:
            for db_file, file_info in db_info['files'].items():
                info_text += f"  • {db_file}: {file_info}\n"
        else:
            info_text += "  No database files found\n"
        
        info_text += "\n" + "="*40 + "\n"
        info_text += "To update the virus database:\n"
        info_text += "1. Connect this USB to a computer with internet\n"
        info_text += "2. Run the update_clamav_db.py script from the USB root directory\n"
        info_text += "3. The script will download and install latest definitions\n"
        
        messagebox.showinfo("Database Information", info_text)
    
    def refresh_disks(self) -> None:
        """Refresh the list of available disks"""
        self.update_log("Refreshing disk list...")
        
        # Clear existing selections
        self.disk_listbox.delete(0, tk.END)
        self.selected_disk_var.set("")
        
        # Get disk list and active disks
        self.disks = get_disk_list()
        active_disk_list = get_active_disk()
        
        if active_disk_list:
            # Convert to base disk names and store as set
            self.active_disks = {get_base_disk(disk) for disk in active_disk_list}
            log_info(f"Active disks detected: {self.active_disks}")
        else:
            self.active_disks = set()
        
        if not self.disks:
            self.update_log("No disks found.")
            self.disk_warning_var.set("No disks available")
            return
        
        # Populate listbox
        for disk in self.disks:
            device_name = disk['device'].replace('/dev/', '')
            base_device = get_base_disk(device_name)
            
            try:
                disk_serial = get_disk_serial(device_name)
                is_device_ssd = is_ssd(device_name)
                ssd_indicator = " (SSD)" if is_device_ssd else " (HDD)"
                
                # Check if this is an active disk
                is_active = base_device in self.active_disks
                active_indicator = " [SYSTEM DISK]" if is_active else ""
                
                disk_info = f"{disk_serial}{ssd_indicator} - {disk['size']}{active_indicator}"
                
                # Add to listbox
                self.disk_listbox.insert(tk.END, disk_info)
                if is_active:
                    # Change color for active disks
                    self.disk_listbox.itemconfig(tk.END, {'fg': 'orange'})
                    
            except Exception as e:
                self.update_log(f"Error getting info for {device_name}: {str(e)}")
        
        # Update warning messages
        if self.active_disks:
            warning_msg = f"WARNING: System disks ({', '.join(self.active_disks)}) detected - scan with caution"
            self.disk_warning_var.set(warning_msg)
        else:
            self.disk_warning_var.set("")
        
        self.update_disk_info()
        self.update_log(f"Found {len(self.disks)} disks")
    
    def on_disk_select(self, event) -> None:
        """Handle disk selection"""
        selection = self.disk_listbox.curselection()
        if selection:
            index = selection[0]
            if index < len(self.disks):
                disk = self.disks[index]
                self.selected_disk_var.set(disk['device'])
                self.update_disk_info()
    
    def update_disk_info(self) -> None:
        """Update the information display for selected disk"""
        selected_device = self.selected_disk_var.get()
        
        if selected_device:
            selected_disk = next((d for d in self.disks if d['device'] == selected_device), None)
            if selected_disk:
                device_name = selected_device.replace('/dev/', '')
                base_device = get_base_disk(device_name)
                
                try:
                    disk_serial = get_disk_serial(device_name)
                    is_device_ssd = is_ssd(device_name)
                    disk_type = "SSD" if is_device_ssd else "HDD"
                    
                    is_active = base_device in self.active_disks
                    system_status = " (SYSTEM DISK)" if is_active else ""
                    
                    # Get partition information
                    partitions = self.get_disk_partitions(selected_device)
                    partition_info = f"\nPartitions: {len(partitions)} found" if partitions else "\nPartitions: None detected"
                    
                    info = (f"Selected: {disk_serial}{system_status}\n"
                           f"Device: {selected_device}\n"
                           f"Type: {disk_type}\n"
                           f"Size: {selected_disk['size']}\n"
                           f"Model: {selected_disk['model']}{partition_info}")
                    
                    self.disk_info_var.set(info)
                except Exception as e:
                    self.disk_info_var.set(f"Selected: {selected_device}\nError getting details: {str(e)}")
        else:
            self.disk_info_var.set("No disk selected")
    
    def start_scan(self) -> None:
        """Start the virus scan process"""
        selected_device = self.selected_disk_var.get()
        
        if not selected_device:
            messagebox.showwarning("Selection Required", "Please select a disk to scan!")
            return
        
        # Check database status first
        db_info = self.get_database_info()
        if db_info['status'] == 'MISSING':
            result = messagebox.askyesno("Database Missing", 
                                       "ClamAV virus database is missing or incomplete!\n\n"
                                       "The scan may not detect many threats.\n\n"
                                       "To update the database:\n"
                                       "1. Connect this USB to a computer with internet\n"
                                       "2. Run update_clamav_db.py from the USB root directory\n\n"
                                       "Continue with scan anyway?")
            if not result:
                return
        elif db_info['status'] == 'OUTDATED':
            result = messagebox.askyesno("Database Outdated", 
                                       "ClamAV virus database may be outdated.\n\n"
                                       "For best protection, update the database using\n"
                                       "update_clamav_db.py from the USB root directory.\n\n"
                                       "Continue with current database?")
            if not result:
                return
        
        # Get disk information for confirmation
        selected_disk = next((d for d in self.disks if d['device'] == selected_device), None)
        
        if not selected_disk:
            messagebox.showerror("Error", "Could not find disk information!")
            return
        
        # Get disk serial for display
        try:
            disk_serial = get_disk_serial(selected_device.replace('/dev/', ''))
        except Exception:
            disk_serial = selected_device
        
        # Show confirmation dialog
        scan_mode = "Deep scan (all partitions)" if self.scan_mode_var.get() == "deep" else "Quick scan (mounted partitions only)"
        remove_text = "REMOVE INFECTED FILES" if self.remove_infected_var.get() else "report only"
        
        device_name = selected_device.replace('/dev/', '')
        base_device = get_base_disk(device_name)
        is_system_disk = base_device in self.active_disks
        
        warning_text = ""
        if is_system_disk:
            warning_text = "\n\n⚠️  WARNING: This is a system disk! Scanning may affect system performance."
        if self.remove_infected_var.get():
            warning_text += "\n\n🚨 DANGER: Infected files will be PERMANENTLY DELETED!"
        
        confirm_msg = (f"Virus scan configuration:\n\n"
                      f"Target: {disk_serial} ({selected_disk['size']})\n"
                      f"Device: {selected_device}\n\n"
                      f"Mode: {scan_mode}\n"
                      f"Action: {remove_text}\n"
                      f"Database: {db_info['status']}\n"
                      f"{warning_text}\n\n"
                      f"Proceed with virus scan?")
        
        if not messagebox.askyesno("Confirm Virus Scan", confirm_msg):
            return
        
        # Additional confirmation for dangerous operations
        if self.remove_infected_var.get():
            if not messagebox.askyesno("FINAL WARNING", 
                                      "You have chosen to REMOVE infected files!\n\n"
                                      "This action is IRREVERSIBLE and may damage your system!\n\n"
                                      "Are you absolutely sure?"):
                return
        
        # Start scanning in a separate thread
        self.is_scanning = True
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.progress.configure(mode='indeterminate')
        self.progress.start()
        
        # Reset scan results
        self.scan_results = {'scanned': 0, 'infected': 0, 'threats': []}
        self.scanned_var.set("Files scanned: 0")
        self.infected_var.set("Threats found: 0")
        
        scan_thread = threading.Thread(target=self.scan_disk_thread, 
                                     args=(selected_device,), daemon=True)
        scan_thread.start()
    
    def scan_disk_thread(self, device: str) -> None:
        """Thread function for virus scanning"""
        try:
            # Perform the actual scan
            self.perform_virus_scan(device)
            
            if self.is_scanning:
                self.status_var.set("Virus scan completed successfully!")
                self.update_log("Virus scan completed successfully!")
                
                # Show results summary
                summary = (f"Scan completed!\n\n"
                          f"Files scanned: {self.scan_results['scanned']}\n"
                          f"Threats found: {self.scan_results['infected']}\n")
                
                if self.scan_results['threats']:
                    summary += f"\nThreats detected:\n" + "\n".join(self.scan_results['threats'][:10])
                    if len(self.scan_results['threats']) > 10:
                        summary += f"\n... and {len(self.scan_results['threats']) - 10} more"
                
                if self.scan_results['infected'] > 0:
                    messagebox.showwarning("Threats Detected", summary)
                else:
                    messagebox.showinfo("Scan Complete", summary)
        
        except Exception as e:
            error_msg = f"Error during virus scan: {str(e)}"
            self.status_var.set("Virus scan failed!")
            self.update_log(error_msg)
            log_error(error_msg)
            messagebox.showerror("Scan Error", error_msg)
        
        finally:
            self.is_scanning = False
            self.start_button.configure(state=tk.NORMAL)
            self.stop_button.configure(state=tk.DISABLED)
            self.progress.stop()
            self.progress.configure(mode='determinate')
    
    def perform_virus_scan(self, device: str) -> None:
        """Perform the actual virus scan"""
        self.update_log(f"Starting virus scan on {device}...")
        self.status_var.set("Scanning for viruses...")
        
        # Build clamscan command
        cmd = ["clamscan"]
        
        # Add options based on user selection
        if self.remove_infected_var.get():
            cmd.append("--remove")
        
        cmd.extend([
            "--recursive",
            "--verbose",
            "--stdout",  # Ensure output goes to stdout
            "--log=/var/log/disk_erase.log"
        ])
        
        # Don't use --infected flag as it suppresses file counting
        # Don't use --no-summary as we need the final summary
        
        # Determine scan targets based on mode
        scan_targets = []
        mount_points = []  # Keep track of mount points we create
        
        try:
            if self.scan_mode_var.get() == "deep":
                # Deep scan - mount all partitions and scan them
                partitions = self.get_disk_partitions(device)
                
                if not partitions:
                    self.update_log(f"No partitions found on {device}, skipping deep scan")
                    # Fallback to quick scan mode
                    scan_targets = ["/"]
                else:
                    self.update_log(f"Found {len(partitions)} partitions on {device}")
                    
                    for partition in partitions:
                        # Create temporary mount point
                        mount_point = f"/tmp/virus_scan_{partition.replace('/', '_')}_{int(time.time())}"
                        
                        try:
                            os.makedirs(mount_point, exist_ok=True)
                            
                            # Try to mount the partition read-only
                            mount_result = subprocess.run(
                                ["mount", "-o", "ro", partition, mount_point],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30
                            )
                            
                            if mount_result.returncode == 0:
                                scan_targets.append(mount_point)
                                mount_points.append(mount_point)
                                self.update_log(f"Mounted {partition} at {mount_point}")
                            else:
                                self.update_log(f"Failed to mount {partition}: {mount_result.stderr.strip()}")
                                # Clean up failed mount point
                                try:
                                    os.rmdir(mount_point)
                                except:
                                    pass
                                    
                        except subprocess.TimeoutExpired:
                            self.update_log(f"Mount timeout for {partition}")
                            try:
                                os.rmdir(mount_point)
                            except:
                                pass
                        except Exception as e:
                            self.update_log(f"Error mounting {partition}: {str(e)}")
                            try:
                                os.rmdir(mount_point)
                            except:
                                pass
                    
                    if not scan_targets:
                        self.update_log("No partitions could be mounted, falling back to quick scan")
                        scan_targets = ["/"]
            else:
                # Quick scan - scan currently mounted filesystems
                scan_targets = ["/"]
                self.update_log("Quick scan mode: scanning mounted filesystems")
            
            # Add scan targets to command
            cmd.extend(scan_targets)
            self.update_log(f"Scan command: {' '.join(cmd)}")
            self.update_log(f"Scanning targets: {', '.join(scan_targets)}")
            
            # Run the scan
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, text=True, bufsize=1, 
                                     universal_newlines=True)
            
            # Monitor the scan output
            files_scanned = 0
            last_update_time = time.time()
            
            while process.poll() is None and self.is_scanning:
                try:
                    output = process.stdout.readline()
                    if output:
                        line = output.strip()
                        if line:
                            self.parse_scan_output(line)
                            
                            # Update progress every second or every 100 files
                            current_time = time.time()
                            if (current_time - last_update_time > 1.0 or 
                                self.scan_results['scanned'] % 100 == 0):
                                self.scanned_var.set(f"Files scanned: {self.scan_results['scanned']}")
                                self.root.update_idletasks()
                                last_update_time = current_time
                
                except Exception as e:
                    log_warning(f"Error reading scan output: {str(e)}")
                
                time.sleep(0.01)  # Reduced sleep time for more responsive updates
            
            # Get any remaining output if scan completed
            if self.is_scanning and process.poll() is not None:
                try:
                    remaining_output, _ = process.communicate(timeout=5)
                    if remaining_output:
                        for line in remaining_output.split('\n'):
                            line = line.strip()
                            if line:
                                self.parse_scan_output(line)
                        
                except subprocess.TimeoutExpired:
                    self.update_log("Timeout waiting for final scan output")
                    process.kill()
            else:
                # Scan was stopped by user
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        
        except Exception as e:
            raise Exception(f"Scan execution failed: {str(e)}")
        
        finally:
            # Cleanup all mount points
            for mount_point in mount_points:
                try:
                    self.update_log(f"Unmounting {mount_point}")
                    subprocess.run(["umount", mount_point], 
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                    os.rmdir(mount_point)
                    self.update_log(f"Cleaned up {mount_point}")
                except subprocess.TimeoutExpired:
                    self.update_log(f"Timeout unmounting {mount_point}")
                    try:
                        subprocess.run(["umount", "-f", mount_point], timeout=5)
                        os.rmdir(mount_point)
                    except:
                        log_warning(f"Failed to force unmount {mount_point}")
                except Exception as e:
                    log_warning(f"Cleanup failed for {mount_point}: {str(e)}")
    
    def parse_scan_output(self, output: str) -> None:
        """Parse real-time scan output"""
        # ClamAV verbose output patterns:
        # - File being scanned: "filename: OK" or "filename: FOUND"
        # - Summary lines contain colons like "Scanned files: 12345"
        
        if not output or len(output.strip()) == 0:
            return
            
        line = output.strip()
        
        # Check for infected files (highest priority)
        if " FOUND" in line or line.endswith(" FOUND"):
            self.scan_results['infected'] += 1
            threat_info = line
            self.scan_results['threats'].append(threat_info)
            self.update_log(f"🚨 THREAT: {threat_info}")
            self.infected_var.set(f"Threats found: {self.scan_results['infected']}")
            return
        
        # Check for summary information
        if ":" in line:
            # Parse summary lines that appear during and at end of scan
            if line.startswith("Scanned files:"):
                try:
                    scanned = int(line.split(':')[1].strip())
                    self.scan_results['scanned'] = scanned
                    return
                except (ValueError, IndexError):
                    pass
            elif line.startswith("Infected files:"):
                try:
                    infected = int(line.split(':')[1].strip())
                    self.scan_results['infected'] = infected
                    self.infected_var.set(f"Threats found: {infected}")
                    return
                except (ValueError, IndexError):
                    pass
        
        # Check for file scanning (ends with ": OK" or similar)
        if line.endswith(": OK") or line.endswith(": Empty file"):
            # This is a successfully scanned file
            self.scan_results['scanned'] += 1
            return
        
        # Check for other scan result indicators
        if ": " in line and (line.endswith(" OK") or 
                            line.endswith(" Empty file") or 
                            line.endswith(" Excluded")):
            self.scan_results['scanned'] += 1
            return
        
        # If it's a path-like string without result indicators, it might be a file being processed
        if (line.startswith('/') and 
            not line.endswith(':') and 
            ":" not in line and
            len(line) > 10):  # Reasonable path length
            self.scan_results['scanned'] += 1
            return
    
    def parse_final_results(self, output: str) -> None:
        """Parse final scan results"""
        if not output:
            return
            
        lines = output.split('\n')
        summary_section = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Look for the summary section
            if "SCAN SUMMARY" in line or line.startswith("-------"):
                summary_section = True
                continue
                
            # Parse summary data
            if ":" in line:
                if "Scanned files:" in line or "scanned files:" in line:
                    try:
                        scanned = int(line.split(':')[1].strip())
                        self.scan_results['scanned'] = max(self.scan_results['scanned'], scanned)
                        self.scanned_var.set(f"Files scanned: {self.scan_results['scanned']}")
                    except (ValueError, IndexError):
                        pass
                elif "Infected files:" in line or "infected files:" in line:
                    try:
                        infected = int(line.split(':')[1].strip())
                        self.scan_results['infected'] = max(self.scan_results['infected'], infected)
                        self.infected_var.set(f"Threats found: {self.scan_results['infected']}")
                    except (ValueError, IndexError):
                        pass
                elif "Engine version:" in line:
                    self.update_log(f"ClamAV {line}")
                elif "Known viruses:" in line:
                    self.update_log(f"Database contains {line}")
            
            # Parse any remaining threat information
            if "FOUND" in line and line not in self.scan_results['threats']:
                self.scan_results['threats'].append(line)
                self.update_log(f"🚨 THREAT: {line}")
        
        # Final update of the display
        self.scanned_var.set(f"Files scanned: {self.scan_results['scanned']}")
        self.infected_var.set(f"Threats found: {self.scan_results['infected']}")
        
        # Log final summary
        self.update_log(f"Scan completed: {self.scan_results['scanned']} files scanned, "
                       f"{self.scan_results['infected']} threats found")
    
    def stop_scan(self) -> None:
        """Stop the scanning process"""
        if self.is_scanning:
            if messagebox.askyesno("Confirm Stop", 
                                  "Are you sure you want to stop the virus scan?"):
                self.is_scanning = False
                self.update_log("Virus scan stopped by user")
                self.status_var.set("Virus scan stopped")
    
    def toggle_fullscreen(self) -> None:
        """Toggle fullscreen mode"""
        is_fullscreen = self.root.attributes("-fullscreen")
        self.root.attributes("-fullscreen", not is_fullscreen)
    
    def exit_application(self) -> None:
        """Exit the application"""
        if self.is_scanning:
            if not messagebox.askyesno("Scan in Progress", 
                                      "A virus scan is in progress.\n\n"
                                      "Are you sure you want to exit?"):
                return
            self.is_scanning = False
        
        log_info("Disk Virus Scanner application closed by user")
        self.root.destroy()
    
    def update_log(self, message: str) -> None:
        """Update the log display"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
        # Also log to file
        log_info(message)