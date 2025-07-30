#!/usr/bin/env python3

import os
import sys
import tkinter as tk
from tkinter import messagebox
from gui import VirusScannerGUI
from log_handler import log_info

def main():
    """Main function to run the virus scanner"""
    # Check for root privileges
    if os.geteuid() != 0:
        print("This program must be run as root!")
        sys.exit(1)
    
    # Initialize the GUI
    root = tk.Tk()
    
    try:
        app = VirusScannerGUI(root)
        root.mainloop()
    except Exception as e:
        error_msg = f"Fatal error starting application: {str(e)}"
        print(error_msg)
        log_info(error_msg)
        
        # Show error dialog if GUI is available
        try:
            messagebox.showerror("Fatal Error", error_msg)
        except:
            pass
        
        sys.exit(1)

if __name__ == "__main__":
    main()