import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import csv

FILENAME = "users.csv"

# Create the file if it doesn't exist
if not os.path.exists(FILENAME):
    with open(FILENAME, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password"])

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def user_exists(username):
    with open(FILENAME, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] == username:
                return True
    return False

def register_user(username, password, window):
    if not username or not password:
        messagebox.showerror("Error", "Please fill in all fields.")
        return
    if user_exists(username):
        messagebox.showerror("Error", "Username already exists.")
        return
    hashed_pwd = hash_password(password)
    with open(FILENAME, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([username, hashed_pwd])
    messagebox.showinfo("Success", "Registration successful!")
    window.destroy()
    show_login()

def login_user(username, password, window):
    hashed_pwd = hash_password(password)
    with open(FILENAME, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] == username and row["password"] == hashed_pwd:
                messagebox.showinfo("Success", "Login successful!")
                window.destroy()
                show_welcome(username)
                return
    messagebox.showerror("Error", "Invalid username or password.")

def reset_password(username, new_password, window):
    if not user_exists(username):
        messagebox.showerror("Error", "Username does not exist.")
        return
    if not new_password:
        messagebox.showerror("Error", "Enter new password.")
        return
    hashed_pwd = hash_password(new_password)
    rows = []
    with open(FILENAME, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] == username:
                row["password"] = hashed_pwd
            rows.append(row)
    with open(FILENAME, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "password"])
        writer.writeheader()
        writer.writerows(rows)
    messagebox.showinfo("Success", "Password reset successful!")
    window.destroy()
    show_login()

# ============ Pages ============

def show_login():
    login = tk.Tk()
    login.title("Login")
    login.geometry("350x300")

    tk.Label(login, text="Login", font=("Helvetica", 16, "bold")).pack(pady=10)

    tk.Label(login, text="Username").pack()
    username_entry = tk.Entry(login)
    username_entry.pack()

    tk.Label(login, text="Password").pack()
    password_entry = tk.Entry(login, show="*")
    password_entry.pack()

    show_var = tk.BooleanVar()
    def toggle_password():
        password_entry.config(show="" if show_var.get() else "*")
    tk.Checkbutton(login, text="Show Password", variable=show_var, command=toggle_password).pack()

    def login_event(event=None):
        login_user(username_entry.get(), password_entry.get(), login)

    password_entry.bind("<Return>", login_event)

    tk.Button(login, text="Login", bg="blue", fg="white", command=login_event).pack(pady=5)
    tk.Button(login, text="Register", command=lambda: [login.destroy(), show_register()]).pack()
    tk.Button(login, text="Forgot Password?", command=lambda: [login.destroy(), show_reset()]).pack()

    login.mainloop()

def show_register():
    register = tk.Tk()
    register.title("Register")
    register.geometry("350x300")

    tk.Label(register, text="Register", font=("Helvetica", 16, "bold")).pack(pady=10)

    tk.Label(register, text="Username").pack()
    username_entry = tk.Entry(register)
    username_entry.pack()

    tk.Label(register, text="Password").pack()
    password_entry = tk.Entry(register, show="*")
    password_entry.pack()

    show_var = tk.BooleanVar()
    def toggle_password():
        password_entry.config(show="" if show_var.get() else "*")
    tk.Checkbutton(register, text="Show Password", variable=show_var, command=toggle_password).pack()

    tk.Button(
        register,
        text="Register",
        bg="green",
        fg="white",
        command=lambda: register_user(username_entry.get(), password_entry.get(), register)
    ).pack(pady=5)

    tk.Button(register, text="Back to Login", command=lambda: [register.destroy(), show_login()]).pack()

    register.mainloop()

def show_reset():
    reset = tk.Tk()
    reset.title("Reset Password")
    reset.geometry("350x250")

    tk.Label(reset, text="Reset Password", font=("Helvetica", 16, "bold")).pack(pady=10)

    tk.Label(reset, text="Username").pack()
    username_entry = tk.Entry(reset)
    username_entry.pack()

    tk.Label(reset, text="New Password").pack()
    password_entry = tk.Entry(reset, show="*")
    password_entry.pack()

    show_var = tk.BooleanVar()
    def toggle_password():
        password_entry.config(show="" if show_var.get() else "*")
    tk.Checkbutton(reset, text="Show Password", variable=show_var, command=toggle_password).pack()

    tk.Button(
        reset,
        text="Reset",
        bg="orange",
        fg="white",
        command=lambda: reset_password(username_entry.get(), password_entry.get(), reset)
    ).pack(pady=5)

    tk.Button(reset, text="Back to Login", command=lambda: [reset.destroy(), show_login()]).pack()

    reset.mainloop()

def show_welcome(username):
    welcome = tk.Tk()
    welcome.title("Welcome")
    welcome.geometry("300x200")

    tk.Label(welcome, text=f"Welcome, {username}!", font=("Arial", 14)).pack(pady=30)
    tk.Button(welcome, text="Logout", command=lambda: [welcome.destroy(), show_login()]).pack()

    welcome.mainloop()

# ============ Start ============

show_login()
