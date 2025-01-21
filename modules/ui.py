import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from modules.profiles import add_user, authenticate_user, load_users, change_username, set_team_member,upload_file_backend
import os
import shutil
import json 
from modules.profiles import find_user_by_username
from modules.profiles import view_password_reset_requests
from modules.profiles import send_password_reset_request, show_uploaded_files, write_log, add_admin
from modules.log_analysis import LogAnomalyDetection
from modules.buttondesign import button_style, button_style_admin, button_style_user
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.fernet import Fernet, InvalidToken
import os
import subprocess
import tkinter as tk
from tkinter import messagebox
import platform

def start_ui():
    root = tk.Tk()
    root.title("FileFlow")
    root.geometry("600x600")
    root.configure(bg="#e6f5f5")
    
    def clear_window():
        for widget in root.winfo_children():
            widget.destroy()

    def go_back():
        clear_window()
        start_screen()

    def start_screen():
        clear_window()  # Yeni ekranı yüklemeden önce eski ekranı temizle
        tk.Label(root, text="FileFlow", font=("Arial", 23), foreground="black", background="#e6f5f5").pack(pady=20, padx=20)
    
        # "Giriş Yap" butonu, sağda hizalanmış
        tk.Button(root, text="Giriş Yap",**button_style, command=individual_login_window).pack(pady=10, padx=15, side=tk.TOP, anchor="e")
    
        # "Kaydol" butonu, sağda hizalanmış
        tk.Button(root, text="Kaydol",**button_style, command=register_window).pack(pady=10, padx=15, side=tk.TOP, anchor="e")
        #tk.Button(root, text="Yönetici Girişi", width=50, height=2, background="#78fafa", command=admin_login_window).pack(pady=10)

    def individual_login_window():
        clear_window()

        tk.Label(root, text="Kullanıcı Adı").pack(pady=5)
        username_entry = tk.Entry(root)
        username_entry.pack(pady=5)

        tk.Label(root, text="Parola").pack(pady=5)
        password_entry = tk.Entry(root, show="*")
        password_entry.pack(pady=5)

        current_user=None
        def login():
            
            global current_user
            username = username_entry.get()
            password = password_entry.get()
            role = authenticate_user(username, password)

            if role == "admin":
                current_user=username
                admin_dashboard()
            elif role == "user":
                current_user=username
                user_dashboard(username)  # username'ı geçiyoruz
            else:
                messagebox.showerror("Giriş Durumu", "Kullanıcı adı veya parola yanlış!")

        tk.Button(root, text="Giriş Yap", command=login).pack(pady=10)
        tk.Button(root, text="Geri", command=go_back).pack(pady=10)

    def change_username_window():
        clear_window()
        tk.Label(root, text="Mevcut Kullanıcı Adı").pack(pady=5)
        old_username_entry = tk.Entry(root)
        old_username_entry.pack(pady=5)
        tk.Label(root, text="Yeni Kullanıcı Adı").pack(pady=5)
        new_username_entry = tk.Entry(root)
        new_username_entry.pack(pady=5)

        def change_username_action():
            old_username = old_username_entry.get()
            new_username = new_username_entry.get()
            result = change_username(old_username, new_username)
            messagebox.showinfo("Kullanıcı Adı Değişim Durumu", result)

        tk.Button(root, text="Kullanıcı Adını Değiştir", command=change_username_action).pack(pady=10)
        tk.Button(root, text="Geri", command=log_out).pack(pady=10)

    def register_window():
        clear_window()

        tk.Label(root, text="Kullanıcı Adı").pack(pady=5)
        username_entry = tk.Entry(root)
        username_entry.pack(pady=5)

        tk.Label(root, text="Parola").pack(pady=5)
        password_entry = tk.Entry(root, show="*")
        password_entry.pack(pady=5)

        def register():
            username = username_entry.get()
            password = password_entry.get()
            result = add_user(username, password)
            messagebox.showinfo("Kayıt Durumu", result)

        tk.Button(root, text="Kayıt Ol", command=register).pack(pady=10)
        tk.Button(root, text="Geri", command=go_back).pack(pady=10)

    def admin_login_window():
        clear_window()

        tk.Label(root, text="Yönetici Girişi", font=("Arial", 16)).pack(pady=20)

        tk.Label(root, text="Kullanıcı Adı").pack(pady=5)
        username_entry = tk.Entry(root)
        username_entry.pack(pady=5)

        tk.Label(root, text="Parola").pack(pady=5)
        password_entry = tk.Entry(root, show="*")
        password_entry.pack(pady=5)

        def login():
            username = username_entry.get()
            password = password_entry.get()
            role = authenticate_user(username, password)

            if role == "admin":
                admin_dashboard()
            else:
                messagebox.showerror("Giriş Durumu", "Yönetici girişi başarısız!")

        tk.Button(root, text="Giriş Yap", command=login).pack(pady=10)
        tk.Button(root, text="Geri", command=go_back).pack(pady=10)

    def admin_dashboard():
        clear_window()

        tk.Label(root, text="Yönetici Paneline Hoşgeldiniz", font=("Arial", 16)).pack(pady=20)
        tk.Button(root, text="Kullanıcıları Görüntüle", command=view_users).pack(pady=10)
        tk.Button(root, text="Logları Görüntüle", command=view_logs).pack(pady=10)
        tk.Button(root,text="Anomaliler",command=view_anomalies).pack(pady=10)
        tk.Button(root,text="Şifre Yenileme Talepleri",command=show_password_requests).pack(pady=10)
        tk.Button(root,text="Yeni Admin Ekleme",command=add_admin_window).pack(pady=10)
        tk.Button(root,text="Oturumu Kapat",command=log_out).pack(pady=10)
        

    def user_dashboard(username):
        clear_window()

        tk.Label(root, text="Kullanıcı Paneline Hoşgeldiniz", font=("Arial", 16)).pack(pady=20)
        tk.Button(root, text="Bireysel Dosya Yükle", command=lambda: file_upload(username)).pack(pady=10)
        tk.Button(root,text="Takıma Dosya Yükle",command=lambda: team_file_upload(username)).pack(pady=10)
        tk.Button(root, text="Dosyalarım", command=view_files).pack(pady=10)
        tk.Button(root,text="Takım Dosyaları",command=open_team_folder).pack(pady=10)
        tk.Button(root, text="Kullanıcı Adımı Değiştir", command=change_username_window).pack(pady=10)
        tk.Button(root, text="Takım Arkadaşı Belirle", command=lambda: select_team_member_window(username)).pack(pady=10)
        tk.Button(root,text="Şifre Sıfırlama Talebi Gönder",command=reset_password).pack(pady=10)
        tk.Button(root, text="Oturumu kapat", command=log_out).pack(pady=10)
    
        
    def select_team_member_window(logged_in_user):
        clear_window()

        tk.Label(root, text="Takım Arkadaşı Seç", font=("Arial", 16)).pack(pady=20)

        tk.Label(root, text="Takım Arkadaşı Kullanıcı Adı").pack(pady=5)
        team_member_username_entry = tk.Entry(root)
        team_member_username_entry.pack(pady=5)

        tk.Label(root, text="Takım Adı").pack(pady=5)
        team_name_entry = tk.Entry(root)
        team_name_entry.pack(pady=5)

        def assign_team_member():
            username = team_member_username_entry.get()
            team_name = team_name_entry.get()

            result = set_team_member(username, team_name, role="user", logged_in_user=logged_in_user)
            messagebox.showinfo("Takım Arkadaşı Belirleme", result)

        tk.Button(root, text="Takım Arkadaşı Belirle", command=assign_team_member).pack(pady=10)
        tk.Button(root, text="Geri", command=user_dashboard).pack(pady=10)

    def view_users():
        clear_window()

        data = load_users()
        users = data.get("users", [])

        tk.Label(root, text="Kullanıcı Listesi", font=("Arial", 16)).pack(pady=20)

        if not users:
            tk.Label(root, text="Hiç kullanıcı bulunmuyor!").pack(pady=10)
        else:
            for user in users:
                user_info = f"Username: {user['username']} - Role: {user['role']} - Team: {user.get('team', 'Belirtilmemiş')}"
                tk.Label(root, text=user_info).pack(pady=5)

        tk.Button(root, text="Geri", command=admin_dashboard).pack(pady=10)

    def view_logs():
        clear_window()

        log_file_path = os.path.join(os.getcwd(), "log.txt")

        tk.Label(root, text="Loglar", font=("Arial", 16), fg="black").pack(pady=20)

        if not os.path.exists(log_file_path):
            tk.Label(root, text=f"Log dosyası bulunamadı! ({log_file_path})", font=("Arial", 12), fg="red").pack(pady=10)
        else:
            with open(log_file_path, "r") as file:
                logs = file.readlines()
                if not logs:
                    tk.Label(root, text="Log dosyasında kayıt bulunmuyor!").pack(pady=10)
                else:
                    
                    with open(log_file_path, "r") as file:
                        logs = file.readlines()
            if not logs:
                tk.Label(root, text="Log dosyasında kayıt bulunmuyor!").pack(pady=10)
            else:
                # Scrollable text widget
                log_text = tk.Text(root, height=15, width=80, wrap=tk.WORD)
                log_text.pack(pady=10)

                # Adding scrollbar
                scrollbar = tk.Scrollbar(root, command=log_text.yview)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                log_text.config(yscrollcommand=scrollbar.set)

                # Insert logs into the text widget
                for log in logs:
                    log_text.insert(tk.END, log.strip() + "\n")

                log_text.config(state=tk.DISABLED)  # Disable editing
                tk.Button(root, text="Geri", command=admin_dashboard).pack(pady=10)
    def view_anomalies():
        clear_window()

        anomaly_file_path = os.path.join(os.getcwd(), "anomaly_log.txt")

        tk.Label(root, text="Anomaliler", font=("Arial", 16), fg="black").pack(pady=20)

        if not os.path.exists(anomaly_file_path):
            tk.Label(root, text=f"Log dosyası bulunamadı! ({anomaly_file_path})", font=("Arial", 12), fg="red").pack(pady=10)
        else:
            with open(anomaly_file_path, "r") as file:
                anomalies = file.readlines()
                if not anomalies:
                    tk.Label(root, text="Anolali dosyasında kayıt bulunmuyor!").pack(pady=10)
                else:
                    
                    with open(anomaly_file_path, "r") as file:
                        logs = file.readlines()
            if not anomalies:
                tk.Label(root, text="Anomali dosyasında kayıt bulunmuyor!").pack(pady=10)
            else:
                # Scrollable text widget
                anomalies_text = tk.Text(root, height=15, width=80, wrap=tk.WORD)
                anomalies_text.pack(pady=10)

                # Adding scrollbar
                scrollbar = tk.Scrollbar(root, command=anomalies_text.yview)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                anomalies_text.config(yscrollcommand=scrollbar.set)

                # Insert logs into the text widget
                for log in logs:
                    anomalies_text.insert(tk.END, log.strip() + "\n")

                anomalies_text.config(state=tk.DISABLED)  # Disable editing
   
        tk.Button(root, text="Geri", command=admin_dashboard).pack(pady=10)

    def manage_files():
        clear_window()
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
    
    def file_upload(username):
        file_path = filedialog.askopenfilename()  # Dosya seçme penceresi
        if file_path:
            # Dosyanın boyutunu kontrol et
            file_size = os.path.getsize(file_path)
        
        if file_size > MAX_FILE_SIZE:
            messagebox.showerror("Hata", "Dosya boyutu 5 MB'yi aşamaz!")
            write_log(f"Hata: {username} kullanıcısı, {os.path.basename(file_path)} adlı dosyayı yüklemeye çalıştı, ancak dosya boyutu çok büyük.")
            return
        # Kullanıcıya özel dizin oluştur
        user_dir = os.path.join('storage', username)  # Kullanıcı adını içeren klasör
        if not os.path.exists('storage'):
            os.makedirs('storage')  # storage dizinini oluştur

        if not os.path.exists(user_dir):
            os.makedirs(user_dir)

        # Dosya adını belirle
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(user_dir, file_name)

        # Dosyayı kopyalamak (yeni dizine kopyalamak)
        shutil.copy(file_path, dest_path)

        # Dosya ismini 'users.json' dosyasına kaydet
        users_file = 'C:\\Users\\aciha\\Desktop\\YGI-2\\data\\users.json'
        with open(users_file, 'r') as f:
            users_data = json.load(f)

        # Kullanıcıyı bul ve files anahtarını ekle
        user_found = False
        for user in users_data['users']:
            if user['username'] == username:
                user_found = True
                # Eğer 'files' anahtarı yoksa, ekle
                if 'files' not in user:
                    user['files'] = []
                # Dosya ismini 'files' listesine ekle
                user['files'].append(file_name)
                break

        # Eğer kullanıcı bulunmazsa, hata mesajı göster
        if not user_found:
            messagebox.showerror("Hata", f"Kullanıcı {username} bulunamadı.")
            return

        # Güncellenmiş veriyi 'users.json' dosyasına kaydet
        with open(users_file, 'w') as f:
            json.dump(users_data, f, indent=4)

        messagebox.showinfo("Başarılı", f"Dosya başarıyla yüklendi: {dest_path}")
        write_log(f"Başarılı: {username} kullanıcısı, {file_name} dosyasını yükledi.") 
    def team_file_upload(username):
    # Dosya seçme penceresi
        file_path = filedialog.askopenfilename()  
        if file_path:
        # 'users.json' dosyasını oku
            users_file = 'C:\\Users\\aciha\\Desktop\\YGI-2\\data\\users.json'
        with open(users_file, 'r') as f:
            users_data = json.load(f)

        # Kullanıcıyı bul
        user_found = False
        team_name = ""
        for user in users_data['users']:
            if user['username'] == username:
                user_found = True
                team_name = user['team']  # Kullanıcının takım adı
                break

        # Eğer kullanıcı bulunmazsa, hata mesajı göster
        if not user_found:
            messagebox.showerror("Hata", f"Kullanıcı {username} bulunamadı.")
            return

        # Kullanıcıya ait takım dizini oluştur
        team_dir = os.path.join('storage', team_name)  # Takım adıyla klasör
        if not os.path.exists('storage'):
            os.makedirs('storage')  # 'storage' dizinini oluştur

        if not os.path.exists(team_dir):
            os.makedirs(team_dir)  # Takım klasörünü oluştur

        # Dosya adını belirle
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(team_dir, file_name)

        # Dosyayı kopyalamak
        shutil.copy(file_path, dest_path)

        # Dosya ismini 'users.json' dosyasına kaydet
        with open(users_file, 'r') as f:
            users_data = json.load(f)

        # Kullanıcıyı bul ve 'files' anahtarını ekle
        for user in users_data['users']:
            if user['username'] == username:
                # Eğer 'files' anahtarı yoksa, ekle
                if 'files' not in user:
                    user['files'] = []
                # Dosya ismini 'files' listesine ekle
                user['files'].append(file_name)
                break

        # Güncellenmiş veriyi 'users.json' dosyasına kaydet
        with open(users_file, 'w') as f:
            json.dump(users_data, f, indent=4)

        # Başarılı mesajı
        messagebox.showinfo("Başarılı", f"Dosya başarıyla yüklendi: {dest_path}")    

    

    def reset_password():
        clear_window()    
    

    # Şifre sıfırlama alanlarını yerleştiriyoruz
        tk.Label(root, text="Kullanıcı Adı").pack(pady=5)
        username_entry = tk.Entry(root)
        username_entry.pack(pady=5)

        tk.Label(root, text="Eski Şifre").pack(pady=5)
        old_password_entry = tk.Entry(root, show="*")
        old_password_entry.pack(pady=5)

        tk.Label(root, text="Yeni Şifre").pack(pady=5)
        new_password_entry = tk.Entry(root, show="*")
        new_password_entry.pack(pady=5)

    # Şifre sıfırlama talebini gönderme fonksiyonu
        def send_request():
            username = username_entry.get()
            old_password = old_password_entry.get()
            new_password = new_password_entry.get()
        
        # Burada 'send_password_reset_request' fonksiyonunu çağırıyoruz
            result = send_password_reset_request(username, old_password, new_password)
            messagebox.showinfo("Şifre Yenileme Talebi", result)
            if "başarılı" in result.lower():  # Şifre sıfırlama başarılıysa log yaz
                write_log(f"Başarılı: {username} kullanıcısı şifresini başarıyla sıfırladı.")
            else:  # Şifre sıfırlama başarısızsa log yaz
                write_log(f"Hata: {username} kullanıcısı şifre sıfırlama girişimi başarısız oldu.")

    # Talep gönderme butonu
        tk.Button(root, text="Talebi Gönder", command=send_request).pack(pady=10)
    
    # Geri butonu
        tk.Button(root, text="Oturumu Kapat", command=log_out).pack(pady=10)

    
    def show_password_requests():
        clear_window()

        request_file_path = os.path.join(os.getcwd(), "password_reset_requests.json")

        tk.Label(root, text="Talepler", font=("Arial", 16), fg="black").pack(pady=20)

        if not os.path.exists(request_file_path):
            tk.Label(root, text=f"Request dosyası bulunamadı! ({request_file_path})", font=("Arial", 12), fg="red").pack(pady=10)
        else:
            with open(request_file_path, "r") as file:
                requests = file.readlines()
                if not requests:
                    tk.Label(root, text="Request dosyasında kayıt bulunmuyor!").pack(pady=10)
                else:
                    
                    with open(request_file_path, "r") as file:
                        logs = file.readlines()
            if not requests:
                tk.Label(root, text="Request dosyasında kayıt bulunmuyor!").pack(pady=10)
            else:
                # Scrollable text widget
                requests_text = tk.Text(root, height=15, width=80, wrap=tk.WORD)
                requests_text.pack(pady=10)

                # Adding scrollbar
                scrollbar = tk.Scrollbar(root, command=requests_text.yview)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                requests_text.config(yscrollcommand=scrollbar.set)

                # Insert logs into the text widget
                for log in requests:
                    requests_text.insert(tk.END, log.strip() + "\n")

                requests_text.config(state=tk.DISABLED)  # Disable editing
        tk.Button(root,text="Talepleri Onayla",command=approve_password_requests).pack(pady=10)
        tk.Button(root, text="Geri", command=admin_dashboard).pack(pady=10)
    
    
    
    def anomaly_analysis():
        if __name__ == "__main__":
            log_file = "C:\\Users\\aciha\\Desktop\\YGI-2\\log.txt"  # Log dosyanızın yolu
            detector = LogAnomalyDetection(log_file)
            detector.run()
       
    
    def view_files():
        clear_window()
        global current_user
    # JSON dosyasının yolu
        files_file_path = os.path.join(os.getcwd(), "data/users.json")

        tk.Label(root, text="Kullanıcı Dosyaları", font=("Arial", 16), fg="black").pack(pady=20)

        if not os.path.exists(files_file_path):
            tk.Label(root, text=f"users.json dosyası bulunamadı! ({files_file_path})", font=("Arial", 12), fg="red").pack(pady=10)
        else:
            with open(files_file_path, "r") as file:
                data = json.load(file)  # JSON verisini yükle
        
        # Giriş yapan kullanıcının dosyalarını al
            user_files = None
        for user in data.get("users", []):
            if user.get("username") ==current_user:
                user_files = user.get("files", [])
                break

        # Kullanıcı dosyalarını göster
        if user_files:
            tk.Label(root, text=f"{current_user} kullanıcısının dosyaları:", font=("Arial", 12)).pack(pady=10)
            files_text = tk.Text(root, height=15, width=80, wrap=tk.WORD)
            files_text.pack(pady=10)
            for file in user_files:
                

                files_text.insert(tk.END, file + "\n")
            files_text.config(state=tk.DISABLED)  # Düzenlemeyi devre dışı bırak
        else:
            tk.Label(root, text=f"{current_user} kullanıcısının dosyası bulunamadı.", font=("Arial", 12), fg="blue").pack(pady=10)

    # Geri dönme butonu
    tk.Button(root, text="Geri", command=admin_dashboard).pack(pady=10)

    
    

    

    def view_team_files():
        clear_window()
    global current_user, current_team
    current_user=None
    # current_user'dan current_team'i belirleyelim
    current_team = None
    files_file_path = os.path.join(os.getcwd(), "data/users.json")

    tk.Label(root, text="Takım Dosyaları", font=("Arial", 16), fg="black").pack(pady=20)

    if not os.path.exists(files_file_path):
        tk.Label(root, text=f"users.json dosyası bulunamadı! ({files_file_path})", font=("Arial", 12), fg="red").pack(pady=10)
    else:
        with open(files_file_path, "r") as file:
            data = json.load(file)  # JSON verisini yükle

            # current_user'a göre current_team'i bulalım
            for user in data.get("users", []):
                if user.get("username") == current_user:
                    current_team = user.get("team")
                    break

            # current_team'in doğru alındığını kontrol et
            print(f"Mevcut takım: {current_team}")

            # Takım dosyalarını al
            team_files = None  # Dosyaların başta boş olduğunu belirtelim
            for user in data.get("users", []):
                if user.get("team") == current_team:
                    team_files = user.get("files", [])  # Takım dosyalarını al
                    break

            # Takım dosyalarını göster
            if team_files:  # Eğer dosyalar varsa
                tk.Label(root, text=f"{current_team} takımının dosyaları:", font=("Arial", 12)).pack(pady=10)
                files_text = tk.Text(root, height=15, width=80, wrap=tk.WORD)
                files_text.pack(pady=10)
                for file in team_files:
                    files_text.insert(tk.END, file + "\n")
                files_text.config(state=tk.DISABLED)  # Düzenlemeyi devre dışı bırak
            else:
                tk.Label(root, text=f"{current_team} takımının dosyası bulunamadı.", font=("Arial", 12), fg="blue").pack(pady=10)

    # Geri dönme butonu
    tk.Button(root, text="Geri", command=admin_dashboard).pack(pady=10)
    
    
   
    
    def log_out():
        global current_user
        if current_user:
            write_log(f"{current_user} cikis yapti.")
            messagebox.showinfo("Çıkış", f"{current_user} oturumu kapatti.")
            current_user = None  # Çıkış sonrası oturumu sıfırlıyoruz
        else:
            messagebox.showinfo("Hata", "Cikis yapacak kullaiıci bulunamadi.")

        go_back()
        
            
    def add_admin_window():
            clear_window()
            tk.Label(root, text="Kullanıcı Adı").pack(pady=5)
            adminname_entry = tk.Entry(root)
            adminname_entry.pack(pady=5)
            tk.Label(root,text="Şifre").pack(pady=5)
            adminpassword_entry = tk.Entry(root,show="*")
            adminpassword_entry.pack(pady=5)
            
            def add_admin_action():
                adminname=adminname_entry.get()
                adminpassword=adminpassword_entry.get()
                resultadmin=add_admin(adminname,adminpassword)
                messagebox.showinfo("Admin ekleme durumu",resultadmin)
            
            tk.Button(root,text="Onayla",command=add_admin_action).pack(pady=10)
        
    def decrypt_password(encrypted_password, key):
        # Base64 ile şifreyi çöz
        encrypted_password_bytes = base64.b64decode(encrypted_password)
        
        # AES şifreleme için nonce'u alın (ilk 16 byte)
        nonce = encrypted_password_bytes[:16]
        ciphertext = encrypted_password_bytes[16:]
        
        # AES şifre çözme
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(ciphertext) + decryptor.finalize()

        # Şifrelenecek veri plaintext olarak döndürülür
        return decrypted_password.decode()
        
    
    
    
    
    
    

    def approve_password_requests():
        request_file_path = os.path.join(os.getcwd(), "password_reset_requests.json")
        users_file_path = os.path.join(os.getcwd(), "users.json")

        if not os.path.exists(users_file_path):
            print("Users dosyası bulunamadı!")
            return

        if not os.path.exists(request_file_path):
            print("Request dosyası bulunamadı!")
            return

        # Kullanıcıları yükle
        with open(users_file_path, 'r') as file:
            data = json.load(file)
            users_list = data.get('users', [])

        # Kullanıcı listesini sözlüğe dönüştür
        users = {user['username']: user for user in users_list}

        if not isinstance(users, dict):
            print("Users dosyası beklenen formatta değil!")
            return

        # Talepleri yükle
        with open(request_file_path, "r") as request_file:
            try:
                requests = json.load(request_file)
            except json.JSONDecodeError:
                print("Request dosyası hatalı formatta!")
                return

        if not isinstance(requests, list):
            print("Request dosyası beklenen formatta değil!")
            return

        valid_requests = []
        for request in requests:
            username = request.get("username")
            old_password = request.get("old_password")
            new_password = request.get("new_password")

            # Kullanıcı adı büyük/küçük harf farkını önlemek için normalize edelim
            normalized_username = username.strip().lower()

            print(f"Aranan kullanıcı adı: {normalized_username}")

            if normalized_username in users:
                encrypted_old_password = users[normalized_username]["password"]
                print(f"Bulunan kullanıcı: {normalized_username}, Şifre: {encrypted_old_password}")

                # Şifreyi çöz
                try:
                    decrypted_old_password = decrypt_password(encrypted_old_password)  # Bu fonksiyonu kendinize göre yazmalısınız
                    if decrypted_old_password == old_password:
                        # Yeni şifreyi şifrele ve güncelle
                        encrypted_new_password = encrypt_password(new_password)  # Bu fonksiyonu kendinize göre yazmalısınız
                        users[normalized_username]["password"] = encrypted_new_password
                        valid_requests.append(normalized_username)
                    else:
                        print(f"{username} kullanıcısının eski şifresi geçersiz!")
                except Exception as e:
                    print(f"{username} kullanıcısının şifresi çözülemedi: {e}")
            else:
                print(f"{username} kullanıcısı bulunamadı!")

        # Güncellenmiş kullanıcıları kaydet
        with open(users_file_path, "w") as users_file:
            json.dump({"users": list(users.values())}, users_file, indent=4)

        # Onaylanan talepleri kaldır
        remaining_requests = [req for req in requests if req.get("username") not in valid_requests]
        with open(request_file_path, "w") as request_file:
            json.dump(remaining_requests, request_file, indent=4)

        print("Tüm geçerli talepler başarıyla onaylandı!")
        clear_window()
        file_path = 'password_reset_requests.json'  # Dosya yolunu buraya yazın
        try:
            # JSON dosyasını açıp içeriğini temizliyoruz
            with open(file_path, 'w') as file:
                json.dump([], file)  # Boş bir liste yaz
            print(f"{file_path} dosyasının içeriği silindi.")
        except Exception as e:
            print(f"Bir hata oluştu: {e}")
        listbox = tk.Listbox(root, height=1, width=2)  # Yüksekliği ve genişliği ihtiyacınıza göre ayarlayabilirsiniz
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar'ı oluştur ve listbox'a bağla
        scrollbar = tk.Scrollbar(root, orient=tk.VERTICAL, command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Listbox'a scrollbar'ı bağla
        listbox.config(yscrollcommand=scrollbar.set)
        tk.Button(root,text="Geri",command=go_back).pack(pady=10)
    # Şifre çözme ve şifreleme fonksiyonlarının örnek halleri

    def encrypt_password(password, key):
        iv = os.urandom(16)  # IV oluşturuluyor
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_password = encryptor.update(password.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_password).decode('utf-8')
        
    
    def decrypt_password(encrypted_password, key):
        encrypted_password_bytes = base64.b64decode(encrypted_password)
        iv = encrypted_password_bytes[:16]  # İlk 16 byte IV
        encrypted_data = encrypted_password_bytes[16:]  # Şifreli veri
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return decrypted_password.decode('utf-8')
            
    


    def open_team_folder():
        clear_window()  # Önceki pencereyi temizle
        
        # Takım adı girişi için bir etiket ve giriş alanı ekleyelim
        tk.Label(root, text="Takım Adını Girin:", font=("Arial", 12)).pack(pady=10)
        
        # Takım adı girişi
        team_entry = tk.Entry(root, font=("Arial", 12))
        team_entry.pack(pady=10)
        
        # Klasör açma butonu
        tk.Button(root, text="Seç", font=("Arial", 12), command=lambda: open_folder(team_entry.get())).pack(pady=20)

        def open_folder(team_name):
            if not team_name:
                messagebox.showerror("Hata", "Takım adı girilmedi!")
                return

            # Klasör yolu
            team_folder_path = os.path.join("C:\\Users\\aciha\\Desktop\\YGI-2\\storage", team_name)

            # Klasörün gerçekten mevcut olup olmadığını kontrol et
            if os.path.exists(team_folder_path):
                try:
                    system_name = platform.system()
                    if system_name == "Windows":
                        subprocess.run(f'explorer "{team_folder_path}"', check=True)
                    elif system_name == "Darwin":  # macOS
                        subprocess.run(f'open "{team_folder_path}"', check=True)
                    elif system_name == "Linux":
                        subprocess.run(f'xdg-open "{team_folder_path}"', check=True)
                    else:
                        messagebox.showerror("Hata", f"{system_name} için desteklenmeyen bir sistem.")
                except subprocess.CalledProcessError:
                    return 
            else:
                messagebox.showerror("Hata", "Belirtilen takım klasörü bulunamadı.")
    
    
    
    
    
    
        
            
    start_screen()  # Program ilk başta start_screen fonksiyonuyla açılır
    root.mainloop()