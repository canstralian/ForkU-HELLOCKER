#! /usr/bin/env python
# -*- coding: utf-8 -*-
import getpass
import os
from tkinter import Tk, Label, Button
from transformers import pipeline

class MachineLearningWinlocker:
    def __init__(self):
        self.user_name = getpass.getuser()
        self.startup_path = fr"C:\Users\{self.user_name}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

        # Load Hugging Face sentiment analysis pipeline
        self.sentiment_analyzer = pipeline("sentiment-analysis")
        print("[+] Sentiment analysis pipeline loaded.")

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

    def analyze_input(self, user_input):
        """Uses Hugging Face sentiment analysis to evaluate user input."""
        try:
            result = self.sentiment_analyzer(user_input)
            sentiment = result[0]
            print(f"[+] Input analysis: {user_input}")
            print(f"    Sentiment: {sentiment['label']} (Score: {sentiment['score']:.2f})")

            # Simulate response based on sentiment
            if sentiment['label'] == "NEGATIVE":
                print("[!] Suspicious or hostile input detected.")
            else:
                print("[+] Input seems normal.")
        except Exception as e:
            print(f"[-] Error analyzing input: {e}")

    def cleanup(self):
        """Simulates cleanup actions after a test."""
        self.remove_persistence()
        print("[+] Cleanup complete.")

if __name__ == "__main__":
    winlocker = MachineLearningWinlocker()

    # Simulate startup persistence
    script_path = os.path.abspath(__file__)
    winlocker.add_persistence(script_path)

    # Simulate a lock screen
    winlocker.lock_screen()

    # Analyze user inputs
    inputs = ["I hate this system", "Everything is fine", "Delete this file now!"]
    for user_input in inputs:
        winlocker.analyze_input(user_input)

    # Perform cleanup
    winlocker.cleanup()