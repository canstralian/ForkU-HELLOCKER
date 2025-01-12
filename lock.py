Here’s the full working code for the improved “HELLOCKER” program with enhanced logging, GUI elements, and better security:

#! /usr/bin/env python
# -*- coding: utf-8 -*-

from tkinter import *
from tkinter import messagebox
from datetime import datetime
import hashlib

# Configuration
PASSWORD = "123"  # Initial password for testing
SALT = "random_salt_value"
ATTEMPT_LIMIT = 3
failed_attempts = []  # List to store failed login attempts
hashed_password = hashlib.sha256((SALT + PASSWORD).encode()).hexdigest()

# Global Variables
attempts_left = ATTEMPT_LIMIT

# Functions
def hash_password(password):
    """Hashes a password with a salt."""
    return hashlib.sha256((SALT + password).encode()).hexdigest()

def validate_password(input_password):
    """Validates the entered password against the hashed password."""
    return hash_password(input_password) == hashed_password

def log_attempt(input_password):
    """Logs a failed password attempt."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    masked_password = "*" * len(input_password)  # Mask password
    failed_attempts.append((timestamp, masked_password))
    update_log_display(timestamp, masked_password)  # Update GUI log

def update_log_display(timestamp, masked_password):
    """Updates the log display in the GUI."""
    log_entry = f"{timestamp}: {masked_password}"
    log_listbox.insert(END, log_entry)
    log_listbox.see(END)

def on_button_click(arg):
    """Handles numeric button clicks."""
    enter_pass.insert(END, arg)

def on_delete_click():
    """Deletes the last character in the password field."""
    enter_pass.delete(len(enter_pass.get()) - 1, END)

def check_password():
    """Checks if the entered password is correct."""
    global attempts_left
    input_password = enter_pass.get()

    if validate_password(input_password):
        messagebox.showinfo("HELLOCKER", "UNLOCKED SUCCESSFULLY")
        window.destroy()  # Exit on successful unlock
    else:
        log_attempt(input_password)
        attempts_left -= 1
        enter_pass.delete(0, END)  # Clear the input field

        if attempts_left == 0:
            messagebox.showwarning("HELLOCKER", "Too many failed attempts.")
            trigger_safe_lock_screen()
        else:
            messagebox.showwarning("HELLOCKER", f"Wrong password. Attempts left: {attempts_left}")

def trigger_safe_lock_screen():
    """Displays a safe lock screen instead of a BSOD."""
    for widget in window.winfo_children():
        widget.destroy()
    Label(window, bg="black", fg="red", text="SYSTEM LOCKED", font="Helvetica 50 bold").pack(pady=20)

def prevent_exit():
    """Prevents the user from closing the window."""
    messagebox.showwarning("HELLOCKER", "Exit is not allowed.")

# GUI Setup
window = Tk()
window.title("HELLOCKER")
window.configure(bg="black")
window.attributes("-fullscreen", True)
window.protocol("WM_DELETE_WINDOW", prevent_exit)

# GUI Components
Label(window, bg="black", fg="red", text="WINDOWS LOCKED BY HELLOCKER", font="Helvetica 50 bold").pack(pady=20)
Label(window, bg="black", fg="red", text="Please enter your password", font="Helvetica 30").pack(pady=20)

enter_pass = Entry(window, bg="black", fg="red", font="Helvetica 25", show="*")
enter_pass.pack(pady=20)

Button(window, text="Unlock", padx=40, pady=20, bg="black", fg="red", font="Helvetica 20", command=check_password).pack(pady=20)

# Numeric Keypad
keypad_frame = Frame(window, bg="black")
keypad_frame.pack()

keypad_buttons = [
    ("1", 1), ("2", 2), ("3", 3),
    ("4", 4), ("5", 5), ("6", 6),
    ("7", 7), ("8", 8), ("9", 9),
    ("0", 0), ("<", "delete")
]

for text, value in keypad_buttons:
    if value == "delete":
        btn = Button(keypad_frame, text=text, padx=20, pady=10, bg="black", fg="red", font="Helvetica 20", command=on_delete_click)
    else:
        btn = Button(keypad_frame, text=text, padx=20, pady=10, bg="black", fg="red", font="Helvetica 20", command=lambda val=text: on_button_click(val))
    btn.pack(side=LEFT, padx=5, pady=5)

# Log Display
log_label = Label(window, text="Failed Attempts Log", bg="black", fg="red", font="Helvetica 20")
log_label.pack(pady=10)

log_listbox = Listbox(window, bg="black", fg="red", font="Helvetica 15", width=50, height=10)
log_listbox.pack(pady=10)

# Run GUI Loop
window.mainloop()

How It Works
	1.	Login System:
      •   User enters their password using the Entry widget or the on-screen keypad.
      •   Passwords are hashed and compared with the stored hashed password.
      •   Failed attempts are logged with timestamps and masked passwords.
	2.	Dynamic Logging:
      •   Logs are displayed in a Listbox and update in real time as users enter incorrect passwords.