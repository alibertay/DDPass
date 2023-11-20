import tkinter as tk
from tkinter import simpledialog, messagebox
import sqlite3
from cryptography.fernet import Fernet
import hashlib
import random
import string
import pyperclip

def CreateMasterKey():
    print("geldi1")
    conn = sqlite3.connect("DDPass.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS user_table (MASTER_KEY TEXT)")
    master_key = cursor.execute("SELECT MASTER_KEY FROM user_table").fetchone()

    if master_key == None:

        fernet_master_key = Fernet.generate_key()
        master_key = str(MakeHash(fernet_master_key)).replace("'","")
        cursor.execute(f"INSERT INTO user_table VALUES('{master_key}')")
        print(master_key)
    else:
        fernet_master_key = Fernet.generate_key()
        master_key = str(MakeHash(fernet_master_key)).replace("'","")
        cursor.execute(f"UPDATE user_table SET MASTER_KEY = '{master_key}'")

    conn.close()

    return str(fernet_master_key)

def GeneratePassword(master_key, platform, username):
    master_key = bytes(master_key)
    master_key_hash = MakeHash(master_key)

    conn = sqlite3.connect("DDPass.db")
    cursor = conn.cursor()
    master_key_hash_from_db = cursor.execute("SELECT MASTER_KEY FROM user_table").fetchone()
    conn.close()

    if master_key_hash_from_db == None:
        raise ValueError("There is no MasterKey for this user.")
    else:
        master_key_hash_from_db = master_key_hash_from_db[0]

    if master_key_hash_from_db == master_key_hash:

        letters = string.ascii_letters
        digits = string.digits
        punctuation = string.punctuation

        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ]
        while len(password) < random.randint(8, 16):
            password.append(random.choice(letters + digits + punctuation))
        random.shuffle(password)

        final_password = ''.join(password)

        cipher = Fernet(master_key)

        encrypted = cipher.encrypt(final_password.encode())

        print("Şifreli Metin:", encrypted)

        conn = sqlite3.connect("DDPass.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS passwords(platform TEXT, username TEXT, password TEXT)")
        cursor.execute(f"INSERT INTO passwords VALUES('{platform}', '{username}', '{encrypted}')")
        conn.close()

        return final_password

    else:
        raise ValueError("Master Key is wrong")

def MakeHash(password):
    password = str(password)
    encoded_message = password.encode()

    sha256_hash = hashlib.sha256(encoded_message)

    return sha256_hash.hexdigest()

def ShowPassword(master_key, platform, username):
    master_key_hash = MakeHash(master_key)

    conn = sqlite3.connect("DDPass.db")
    cursor = conn.cursor()
    master_key_hash_from_db = cursor.execute("SELECT MASTER_KEY FROM user_table").fetchone()
    conn.close()

    if master_key_hash_from_db == None:
        raise ValueError("There is no MasterKey for this user.")
    else:
        master_key_hash_from_db = master_key_hash_from_db[0]

    if master_key_hash_from_db == master_key_hash:
        conn = sqlite3.connect("DDPass.db")
        cursor = conn.cursor()
        password = cursor.execute(f"SELECT password FROM passwords WHERE username = '{username}' AND platform = '{platform}'").fetchone()
        conn.close()

        if password == None:
            raise ValueError(f"There is no password of {username} for {platform}")
        else:
            password = password[0]

        cipher = Fernet(master_key)

        decrypted = cipher.decrypt(password).decode()

        return decrypted

    else:
        raise ValueError("Master Key is wrong.")

def get_platforms_and_usernames():
    conn = sqlite3.connect("DDPass.db")
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT platform FROM passwords")
    platforms = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT username FROM passwords")
    usernames = [row[0] for row in cursor.fetchall()]

    conn.close()
    return platforms, usernames

def update_dropdowns():
    platforms, usernames = get_platforms_and_usernames()
    platform_menu['menu'].delete(0, 'end')
    username_menu['menu'].delete(0, 'end')

    for platform in platforms:
        platform_menu['menu'].add_command(label=platform,
                                          command=tk._setit(platform_var, platform))
    for username in usernames:
        username_menu['menu'].add_command(label=username,
                                          command=tk._setit(username_var, username))

def on_create_master_key():
    master_key = CreateMasterKey()
    master_key_window = tk.Toplevel(root)
    master_key_window.title("Master Key")
    master_key_window.geometry("300x100")

    master_key_entry = tk.Entry(master_key_window, font=("Helvetica", 12), show="*")
    master_key_entry.pack(pady=10)
    master_key_entry.insert(0, master_key)

    def copy_master_key():
        pyperclip.copy(master_key)
        messagebox.showinfo("Copied", "Master key copied to clipboard.")

    copy_button = tk.Button(master_key_window, text="Copy", command=copy_master_key)
    copy_button.pack()

def on_show_password():
    platform = platform_var.get()
    username = username_var.get()
    master_key = simpledialog.askstring("Master Key", "Enter your master key:", show='*')
    if master_key:
        try:
            password = ShowPassword(master_key, platform, username)
            messagebox.showinfo("Password", f"The password is: {password}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

def on_add_new_platform():
    new_platform_window = tk.Toplevel(root)
    new_platform_window.title("Add New Platform")
    new_platform_window.geometry("300x300")

    frame = tk.Frame(new_platform_window, padx=10, pady=10)
    frame.pack(expand=True)

    tk.Label(frame, text="Platform:").pack()
    platform_entry = tk.Entry(frame)
    platform_entry.pack()

    tk.Label(frame, text="Username:").pack()
    username_entry = tk.Entry(frame)
    username_entry.pack()

    password_entry = tk.Entry(frame, font=("Helvetica", 12), show="*")
    password_entry.pack(pady=10)

    def generate_and_show_password():
        platform = platform_entry.get()
        username = username_entry.get()
        master_key = simpledialog.askstring("Master Key", "Enter your master key:", show='*')
        if master_key:
            try:
                password = GeneratePassword(master_key, platform, username)
                password_entry.delete(0, tk.END)
                password_entry.insert(0, password)
            except ValueError as e:
                messagebox.showerror("Error", str(e))

    generate_password_button = tk.Button(frame, text="Generate Password", command=generate_and_show_password)
    generate_password_button.pack()

    def copy_password():
        pyperclip.copy(password_entry.get())
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    copy_password_button = tk.Button(frame, text="Copy Password", command=copy_password)
    copy_password_button.pack()

root = tk.Tk()
root.title("DDPass")
root.geometry("600x600")

# Create Master Key Button
create_master_key_button = tk.Button(root, text="Create Master Key", command=on_create_master_key)
create_master_key_button.place(x=500, y=10)

# Add New Platform Button
add_new_platform_button = tk.Button(root, text="Add New Platform", command=on_add_new_platform)
add_new_platform_button.place(x=10, y=10)

# Dropdown menus and Show Password button frame
dropdown_frame = tk.Frame(root)
dropdown_frame.place(relx=0.5, rely=0.5, anchor='center')

platform_var = tk.StringVar(root)
username_var = tk.StringVar(root)
platform_menu = tk.OptionMenu(dropdown_frame, platform_var, "")
username_menu = tk.OptionMenu(dropdown_frame, username_var, "")
update_dropdowns()

platform_menu.pack()
username_menu.pack()

show_password_button = tk.Button(dropdown_frame, text="Show Password", command=on_show_password)
show_password_button.pack()

root.mainloop()