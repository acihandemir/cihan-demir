import re
from datetime import datetime, timedelta

class UserBehaviorAnalysis:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        # Anahtar kelimeler
        self.keywords = {
            "failed_login": "giris yapmayi denedi ancak başarisiz oldu.",
            "successful_login": "giris yapti",
            "password_change": "parola değiştirme talebi"
        }
        self.anomalies = []
        self.user_failed_logins = {}  # Kullanıcı başına başarısız giriş sayıları
        self.user_password_changes = {}  # Kullanıcı başına parola değiştirme talepleri

    def read_logs(self):
        """Log dosyasını satır satır okur."""
        try:
            with open(self.log_file_path, 'r') as file:
                return file.readlines()
        except FileNotFoundError:
            print("Log dosyası bulunamadı.")
            return []

    def search_keywords(self, logs):
        """Loglarda belirli anahtar kelimeleri arar."""
        keyword_matches = {key: [] for key in self.keywords}
        for line in logs:
            for key, keyword in self.keywords.items():
                if keyword in line:
                    keyword_matches[key].append(line)
        return keyword_matches

    def detect_anomalies(self, logs):
        """Belirli kurallara dayalı anomali tespiti yapar."""
        now = datetime.now()
        time_window = timedelta(minutes=5)  # 5 dakikalık pencere

        for line in logs:
            timestamp = self.extract_timestamp(line)
            if timestamp:
                if now - timestamp < time_window:
                    for key, keyword in self.keywords.items():
                        if keyword in line:
                            user_id = self.extract_user_id(line)
                            if user_id:
                                if key == "failed_login":
                                    self.user_failed_logins[user_id] = self.user_failed_logins.get(user_id, 0) + 1
                                if key == "password_change":
                                    self.user_password_changes[user_id] = self.user_password_changes.get(user_id, 0) + 1

        # Anomalileri kontrol et
        for user_id, failed_attempts in self.user_failed_logins.items():
            if failed_attempts > 3:
                self.anomalies.append(f"UYARI: Kullanıcı {user_id}, kısa bir süre içinde 3'ten fazla başarısız giriş denemesi yaptı.")
                self.send_alert(user_id, "Başarısız giriş denemeleri")

        for user_id, password_changes in self.user_password_changes.items():
            if password_changes > 2:
                self.anomalies.append(f"UYARI: Kullanıcı {user_id}, kısa bir süre içinde sürekli parola değiştirme talebi yaptı.")
                self.send_alert(user_id, "Sürekli parola değiştirme talebi")

    def extract_timestamp(self, log_line):
        """Log satırından zaman damgasını çıkarır."""
        timestamp_format = "%Y-%m-%d %H:%M:%S"
        match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", log_line)
        if match:
            try:
                return datetime.strptime(match.group(), timestamp_format)
            except ValueError:
                print(f"Geçersiz zaman damgası formatı: {log_line}")
        return None

    def extract_user_id(self, log_line):
        """Log satırından kullanıcı kimliğini çıkarır (varsayım olarak)."""
        match = re.search(r"user_id=(\d+)", log_line)
        if match:
            return match.group(1)
        return None

    def send_alert(self, user_id, issue):
        """Anormal durumu tespit edilen kullanıcıya uyarı gönderir."""
        print(f"UYARI: Kullanıcı {user_id}, {issue} - Anormal davranış tespit edildi.")
        with open("user_behavior_log.txt", "a") as log_file:
            log_file.write(f"{datetime.now()}: Kullanıcı {user_id} - {issue} tespit edildi.\n")

    def run(self):
        """Kullanıcı davranışı tespiti sürecini çalıştırır."""
        logs = self.read_logs()
        if logs:
            self.detect_anomalies(logs)

# Örnek kullanım
if __name__ == "__main__":
    log_file = "C:\\Users\\aciha\\Desktop\\YGI-2\\log.txt"  # Log dosyanızın yolu
    analyzer = UserBehaviorAnalysis(log_file)
    analyzer.run()
    print(log_file)