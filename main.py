import tkinter as tk
from tkinter import simpledialog, messagebox
import sqlite3
from cryptography.fernet import Fernet
import hashlib
import random
import string
import pyperclip


def initialize_database():
    conn = sqlite3.connect("DDPass.db")
    cursor = conn.cursor()

    # user_table ve passwords tablolarını oluşturma
    cursor.execute("CREATE TABLE IF NOT EXISTS user_table (MASTER_KEY TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS passwords (platform TEXT, username TEXT, password BLOB)")

    conn.commit()
    conn.close()

def CreateMasterKey():
    user_response = messagebox.askyesno("Confirm", "Creating a new Master Key will delete all existing passwords. Continue?")
    if user_response:
        conn = sqlite3.connect("DDPass.db")
        cursor = conn.cursor()

        # Yeni master key oluştur ve hash'le
        fernet_master_key = Fernet.generate_key()
        hashed_master_key = MakeHash(fernet_master_key)

        # user_table'daki mevcut master key'i güncelle
        cursor.execute("UPDATE user_table SET MASTER_KEY = ?", (hashed_master_key,))

        # passwords tablosundaki tüm verileri sil
        cursor.execute("DELETE FROM passwords")

        conn.commit()
        conn.close()

        return fernet_master_key.decode()  # Yeni Fernet anahtarını döndür
    else:
        raise ValueError("Master Key creation cancelled by user.")


def GeneratePassword(master_key, platform, username):
    master_key_hash = MakeHash(master_key)  # Kullanıcının girdiği anahtarın hash değeri

    conn = sqlite3.connect("DDPass.db")
    cursor = conn.cursor()
    master_key_hash_from_db = cursor.execute("SELECT MASTER_KEY FROM user_table").fetchone()
    conn.close()

    if master_key_hash_from_db is None:
        raise ValueError("There is no MasterKey for this user.")
    else:
        master_key_hash_from_db = master_key_hash_from_db[0]

    if master_key_hash_from_db == master_key_hash:
        # Parola oluşturma
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

        # Şifreleme
        cipher = Fernet(master_key)
        encrypted = cipher.encrypt(final_password.encode())

        # Veritabanında şifre mevcutsa güncelle, yoksa ekle
        conn = sqlite3.connect("DDPass.db")
        cursor = conn.cursor()

        existing_password = cursor.execute("SELECT password FROM passwords WHERE platform = ? AND username = ?",
                                           (platform, username)).fetchone()

        if existing_password:
            cursor.execute("UPDATE passwords SET password = ? WHERE platform = ? AND username = ?",
                           (encrypted, platform, username))
        else:
            cursor.execute("INSERT INTO passwords (platform, username, password) VALUES (?, ?, ?)",
                           (platform, username, encrypted))

        conn.commit()
        conn.close()

        # Yeni pencere oluştur
        password_window = tk.Toplevel(root)
        password_window.title("Generated Password")
        password_window.geometry("300x150")

        tk.Label(password_window, text="Generated Password:").pack()
        generated_password_entry = tk.Entry(password_window, font=("Helvetica", 12), show="*")
        generated_password_entry.pack(pady=10)
        generated_password_entry.insert(0, final_password)

        def copy_generated_password():
            pyperclip.copy(final_password)
            messagebox.showinfo("Copied", "Generated password copied to clipboard.")

        copy_button = tk.Button(password_window, text="Copy", command=copy_generated_password)
        copy_button.pack()

        return final_password
    else:
        raise ValueError("Master Key is wrong")

def MakeHash(password):
    password = str(password)
    encoded_message = password.encode()

    sha256_hash = hashlib.sha256(encoded_message)

    return sha256_hash.hexdigest()

def ShowPassword(master_key, platform, username):
    conn = sqlite3.connect("DDPass.db")
    cursor = conn.cursor()
    password = cursor.execute("SELECT password FROM passwords WHERE username = ? AND platform = ?", (username, platform)).fetchone()
    conn.close()

    if password is None:
        raise ValueError(f"There is no password for {username} on {platform}")
    else:
        password = password[0]

    cipher = Fernet(master_key.encode())
    decrypted = cipher.decrypt(password).decode()

    return decrypted

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

            # Şifreyi gösteren yeni pencere
            password_window = tk.Toplevel(root)
            password_window.title("Password")
            password_window.geometry("300x150")

            # Şifre giriş alanı, başlangıçta gizli
            password_entry = tk.Entry(password_window, font=("Helvetica", 12), show="*")
            password_entry.pack(pady=10)
            password_entry.insert(0, password)

            def toggle_password():
                """Şifreyi göster veya gizle"""
                if password_entry.cget('show') == '*':
                    password_entry.config(show='')
                else:
                    password_entry.config(show='*')

            def copy_password():
                """Şifreyi panoya kopyala"""
                pyperclip.copy(password_entry.get())
                messagebox.showinfo("Copied", "Password copied to clipboard.")

            # Şifreyi göster/gizle butonu
            toggle_button = tk.Button(password_window, text="Show/Hide", command=toggle_password)
            toggle_button.pack()

            # Şifreyi kopyala butonu
            copy_button = tk.Button(password_window, text="Copy", command=copy_password)
            copy_button.pack()

        except ValueError as e:
            messagebox.showerror("Error", str(e))

def on_add_new_platform():
    def generate_and_show_password(master_key_str):
        platform = platform_entry.get()
        username = username_entry.get()

        if platform and username:
            try:
                master_key = bytes(master_key_str, 'utf-8')  # String'i bayt dizisine çevirin
                password = GeneratePassword(master_key, platform, username)
                password_var.set(password)
            except ValueError as e:
                messagebox.showerror("Error", str(e))

    def create_password_window():
        platform = platform_entry.get()
        username = username_entry.get()

        if platform and username:
            password_window = tk.Toplevel(root)
            password_window.title("Generate Password")
            password_window.geometry("300x150")

            tk.Label(password_window, text="Enter your master key:").pack()
            master_key_entry = tk.Entry(password_window, font=("Helvetica", 12), show="*")
            master_key_entry.pack(pady=10)

            generate_password_button = tk.Button(password_window, text="Generate Password",
                                                 command=lambda: generate_and_show_password(master_key_entry.get()))
            generate_password_button.pack()

    new_platform_window = tk.Toplevel(root)
    new_platform_window.title("Add New Platform")
    new_platform_window.geometry("300x150")

    frame = tk.Frame(new_platform_window, padx=10, pady=10)
    frame.pack(expand=True)

    tk.Label(frame, text="Platform:").pack()
    platform_entry = tk.Entry(frame)
    platform_entry.pack()

    tk.Label(frame, text="Username:").pack()
    username_entry = tk.Entry(frame)
    username_entry.pack()

    create_password_button = tk.Button(frame, text="Create Password", command=create_password_window)
    create_password_button.pack()

    password_var = tk.StringVar()
    password_entry = tk.Entry(frame, textvariable=password_var, font=("Helvetica", 12), show="*")
    password_entry.pack(pady=10)

initialize_database()

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
