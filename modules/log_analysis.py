import re
from datetime import datetime, timedelta
import threading
import time

class LogAnomalyDetection:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.keywords = [
            "giris yapmayi denedi ancak basarisiz oldu.",
            "giris yapti",
            "yedekleme kesildi",
            "dosya indirme",
            "dosya yukleme",
            "yetkisiz dosya paylasimi",
            "parola degistirme"
        ]
        self.anomalies = []
        self.running = True  # Thread'in çalışıp çalışmadığını kontrol etmek için

    def read_logs(self):
        """Log dosyasını satır satır okur."""
        try:
            with open(self.log_file_path, 'r') as file:
                return file.readlines()
        except FileNotFoundError:
            print("Log dosyası bulunamadı.")
            return []

    def detect_anomalies(self, logs):
        """Belirli kurallara dayalı anomali tespiti yapar."""
        event_times = {
            "giris yapmayi denedi ancak basarisiz oldu.": [],
            "giris yapti": [],
            "yedekleme kesildi": [],
            "dosya indirme": [],
            "dosya yukleme": [],
            "yetkisiz dosya paylasimi": [],
            "sifre  sıfırlama basarisiz": []
        }
        now = datetime.now()
        time_window = timedelta(minutes=10)  # 10 dakikalık pencere

        for line in logs:
            timestamp = self.extract_timestamp(line)
            if timestamp:
                # Küçük/büyük harf duyarsız arama
                for keyword in self.keywords:
                    if keyword.lower() in line.lower():
                        event_times[keyword].append(timestamp)

        # Anomali koşullarını kontrol et
        if len(event_times["giris yapmayi denedi ancak basarisiz oldu."]) > 3:
            self.anomalies.append("Kısa bir süre içinde 3'ten fazla başarısız giriş denemesi tespit edildi.")
        
        if len(event_times["yedekleme kesildi"]) > 0:
            self.anomalies.append("Yedekleme veya senkronizasyon işlemi beklenmedik şekilde kesildi.")

        if len(event_times["dosya indirme"]) > 5 or len(event_times["dosya yukleme"]) > 5:
            self.anomalies.append("Kısa bir zaman diliminde olağandışı sayıda dosya indirme veya yükleme tespit edildi.")

        if len(event_times["yetkisiz dosya paylasimi"]) > 0:
            self.anomalies.append("Yetkisiz dosya paylaşımı tespit edildi.")

        if len(event_times["parola degistirme"]) > 3:
            self.anomalies.append("Kısa bir zaman diliminde sürekli parola değiştirme talepleri tespit edildi.")

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

    def send_alerts(self):
        """Tespit edilen anomali için uyarılar gönderir."""
        if self.anomalies:
            for anomaly in self.anomalies:
                print(f"UYARI: {anomaly}")
            try:
                with open("anomaly_log.txt", "a") as log_file:
                    for anomaly in self.anomalies:
                        log_file.write(f"{datetime.now()}: {anomaly}\n")
                print("Anomaliler başarıyla 'anomaly_log.txt' dosyasına yazıldı.")
            except Exception as e:
                print(f"Dosyaya yazma hatası: {e}")
        else:
            print("Tespit edilen anomali yok.")

    def run(self):
        """Anomali tespiti sürecini çalıştırır."""
        logs = self.read_logs()
        if logs:
            self.detect_anomalies(logs)
            self.send_alerts()

    def periodic_run(self, interval_seconds):
        """Periyodik olarak anomali tespiti yapar."""
        while self.running:
            print("Anomali tespiti başlatılıyor...")
            self.run()
            print(f"Bir sonraki kontrol için {interval_seconds} saniye bekleniyor.")
            time.sleep(interval_seconds)

    def start_periodic_detection(self, interval_seconds):
        """Periyodik anomali tespiti başlatan thread'i başlatır."""
        anomaly_thread = threading.Thread(target=self.periodic_run, args=(interval_seconds,))
        anomaly_thread.daemon = True  # Ana program bittiğinde thread'in de sonlanmasını sağlar
        anomaly_thread.start()

    def stop(self):
        """Thread'i durdurur."""
        self.running = False

# Örnek kullanım
if __name__ == "__main__":
    log_file = "C:\\Users\\aciha\\Desktop\\YGI-2\\log.txt"  # Log dosyanızın yolu
    detector = LogAnomalyDetection(log_file)
    
    # Periyodik anomali tespiti başlat: 10 dakikada bir kontrol yapacak
    detector.start_periodic_detection(600)

    try:
        while True:
            # Ana döngü devam eder, ancak buradaki kodu kendi programınıza entegre edebilirsiniz
            time.sleep(1)  # Ana programın durmaması için
    except KeyboardInterrupt:
        print("Program sonlandırılıyor...")
        detector.stop()  # Program durdurulurken thread'i durdurur
