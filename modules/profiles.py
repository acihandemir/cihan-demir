import json
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime
import shutil
import os
from tkinter import messagebox, filedialog, Listbox, Button
import tkinter as tk


# Log yazma fonksiyonu
def write_log(message):
    with open("log.txt", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] {message}\n")

# Anahtar yükleme veya oluşturma fonksiyonu
def load_key():
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        write_log("Yeni bir anahtar oluşturuldu.")
        return key

SECRET_KEY = load_key()
cipher = Fernet(SECRET_KEY)

# Kullanıcı verilerini yükleme fonksiyonu
def load_users(file_path="data/users.json"):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        write_log("users.json dosyası bulunamadı, yeni bir dosya oluşturuluyor.")
        return {"users": []}

# Kullanıcı verilerini kaydetme fonksiyonu
def save_users(data, file_path="data/users.json"):
    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)
        write_log(f"Kullanıcı verileri {file_path} dosyasına kaydedildi.")

    
# Şifreyi şifreleme fonksiyonu
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

# Şifre doğrulama fonksiyonu
def verify_password(encrypted_password, plain_password):
    try:
        decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
        return decrypted_password == plain_password
    except InvalidToken:
        return False

# Kullanıcı adının alınıp alınmadığını kontrol etme fonksiyonu
def is_username_taken(username, data):
    for user in data["users"]:
        if user["username"] == username:
            return True
    return False

# Kullanıcı adını değiştirme fonksiyonu
def change_username(old_username, new_username):
    data = load_users()
    user_found = False

    if is_username_taken(new_username, data):
        write_log(f"{new_username} kullanıcı adı zaten alınmış.")
        return "Bu kullanıcı adı zaten alınmış!"

    for user in data["users"]:
        if user["username"] == old_username:
            user_found = True
            user["username"] = new_username
            write_log(f"{old_username} kullanıcı adı {new_username} olarak değiştirildi.")
            break

    if not user_found:
        write_log(f"{old_username} kullanıcı adı bulunamadı.")
        return "Eski kullanıcı adı bulunamadı!"

    save_users(data)
    return "Kullanıcı adı başarıyla değiştirildi!"

# Kullanıcı ekleme fonksiyonu
def add_user(username, password, role="user"):
    data = load_users()

    if is_username_taken(username, data):
        write_log(f"{username} kullanıcı adı zaten alınmış.")
        return "Bu kullanıcı adı zaten alınmış!"

    encrypted_password = encrypt_password(password)
    data["users"].append({"username": username, "password": encrypted_password, "role": role})
    save_users(data)
    write_log(f"Yeni kullanıcı oluşturuldu: {username}, rol: {role}.")
    return "Kullanıcı başarıyla oluşturuldu!"

def add_admin(username, password, role="admin"):
    data = load_users()

    if is_username_taken(username, data):
        write_log(f"{username} kullanıcı adı zaten alınmış.")
        return "Bu kullanıcı adı zaten alınmış!"

    encrypted_password = encrypt_password(password)
    data["users"].append({"username": username, "password": encrypted_password, "role": role})
    save_users(data)
    write_log(f"Yeni kullanıcı oluşturuldu: {username}, rol: {role}.")
    return "Kullanıcı başarıyla oluşturuldu!"


# Kullanıcı kimlik doğrulama fonksiyonu
def authenticate_user(username, password):
    data = load_users()
    for user in data["users"]:
        if user["username"] == username:
            if verify_password(user["password"], password):
                write_log(f"{username} giris yapti.")
                return user["role"]
    write_log(f"{username} giris yapmayi denedi ancak basarisiz oldu.")
    return None

# Takım üyesi atama fonksiyonu
def set_team_member(username, team_name, role, logged_in_user):
    data = load_users()

    for user in data["users"]:
        if user["username"] == logged_in_user:
            user["team"] = team_name
            write_log(f"{logged_in_user} kullanıcısı {team_name} takımına atandı.")
            save_users(data)
            break

    for user in data["users"]:
        if user["username"] == username:
            user["team"] = team_name
            user["role"] = role
            save_users(data)
            write_log(f"{username} kullanıcısı {team_name} takımına {role} rolüyle atandı.")
            return f"{username} has been assigned to team '{team_name}' with role '{role}'."

    write_log(f"{username} için takım atama başarısız oldu: Kullanıcı adı bulunamadı.")
    return "Kullanıcı adı bulunamadı!"

# Bildirim gönderme fonksiyonu
def send_notification(username, message):
    data = load_users()

    for user in data["users"]:
        if user["username"] == username:
            write_log(f"Bildirim gönderildi: {username} - {message}")
            return f"Notification sent to {username}: {message}"

    write_log(f"Bildirim başarısız oldu: {username} kullanıcı adı bulunamadı.")
    return "Kullanıcı adı bulunamadı!"

def is_admin(username, password):
    role = authenticate_user(username, password) #kullanıcı bilgilerini alıyoruz
    if role == "admin":
        return True
    else:
        return False
    
USER_DATA_PATH = 'users.json'

# Yüklenen dosyaların kaydedileceği dizin
UPLOAD_FOLDER = 'uploaded_files/'


   
def find_user_by_username(username):
    user_data = load_users()
    for user in user_data["users"]:
        if user["username"] == username:
            return user
    return None

def upload_file_backend(username):
    file_path = filedialog.askopenfilename()  # Dosya seçme penceresi
    if file_path:
        # Kullanıcıya özel dizin oluştur
        user_dir = os.path.join('storage', username)  # Kullanıcı adını içeren klasör
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)

        # Dosya adını belirle
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(user_dir, file_name)

        # Dosyayı kopyalamak (yeni dizine kopyalamak)
        shutil.copy(file_path, dest_path)

        # Dosya ismini JSON dosyasına kaydet
        users_file = 'users.json'
        with open(users_file, 'r') as f:
            users_data = json.load(f)

        users_data[username]['files'].append(file_name)
        with open(users_file, 'w') as f:
            json.dump(users_data, f)

        messagebox.showinfo("Başarılı", f"Dosya başarıyla yüklendi: {dest_path}")
    else:
        messagebox.showwarning("Hata", "Dosya seçilmedi.")

# Kullanıcının yüklediği dosyaları görüntüleme
def show_uploaded_files(username):
    users_file = 'C:\\Users\\aciha\\Desktop\\YGI-2\\data\\users.json'
    with open(users_file, 'r') as f:
        users_data = json.load(f)

    user_files = users_data.get(username, {}).get('files', [])
    
    if not user_files:
        messagebox.showinfo("Dosya Yok", "Henüz dosya yüklenmedi.")
    else:
        files_window = tk.Tk()
        files_window.title("Yüklenen Dosyalar")
        listbox = Listbox(files_window)
        listbox.pack(pady=20)
        
        for file in user_files:
            listbox.insert('end', file)
        
        Button(files_window, text="Kapat", command=files_window.destroy).pack(pady=20)
        files_window.mainloop()


# Şifre yenileme taleplerini tutmak için dosya yolu
request_file_path = "password_reset_requests.json"

def load_password_reset_requests():
    if os.path.exists(request_file_path):
        with open(request_file_path, "r") as file:
            return json.load(file)
    return []

def save_password_reset_requests(requests):
    with open(request_file_path, "w") as file:
        json.dump(requests, file)


def send_password_reset_request(username, old_password, new_password):
    # Burada kullanıcı doğrulaması yapılabilir.
    # Örnek olarak sadece talep ekliyoruz.
    requests = load_password_reset_requests()
    requests.append({
        'username': username,
        'old_password': old_password,
        'new_password': new_password
    })
    save_password_reset_requests(requests)
    return "Şifre yenileme talebiniz başarıyla gönderildi."

# Admin'in şifre yenileme taleplerini görüntülemesi
def view_password_reset_requests():
    return load_password_reset_requests()

# Admin'in şifre yenileme talebini onaylama
def approve_password_reset(username, new_password, old_password):
    users = load_users()  # Burada kullanıcıları yüklüyoruz
    user = next((u for u in users if u['username'] == username), None)
    if user and verify_password(user['password'], old_password):
        user['password'] = encrypt_password(new_password)
        save_users(users)  # Kullanıcı bilgilerini kaydediyoruz.
        requests = load_password_reset_requests()
        requests = [r for r in requests if r['username'] != username]  # Talebi kaldır
        save_password_reset_requests(requests)
        return "Şifre başarıyla değiştirildi."
    return "Eski şifre yanlış ya da kullanıcı bulunamadı."
