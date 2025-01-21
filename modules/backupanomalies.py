import re
from datetime import datetime, timedelta
import threading
import time

class BackupAnomalyDetection:
    def __init__(self, log_file_path, analysis_file_path):
        self.log_file_path = log_file_path
        self.analysis_file_path = analysis_file_path
        self.keywords = ["Yedekleme baslatildi", "Yedekleme tamamlandi"]
        self.anomalies = []
        self.event_times = {"Yedekleme baslatildi": [], "Yedekleme tamamlandi": []}
        self.last_backup_time = None
        self.running = True

    def read_logs(self):
        """Log dosyasını satır satır okur."""
        try:
            with open(self.log_file_path, 'r') as file:
                return file.readlines()
        except FileNotFoundError:
            print("Log dosyası bulunamadı.")
            return []

    def extract_timestamp(self, line):
        """Log satırından timestamp çıkarır."""
        timestamp_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
        if timestamp_match:
            return datetime.strptime(timestamp_match.group(), "%Y-%m-%d %H:%M:%S")
        return None

    def detect_anomalies(self, logs):
        """Yedekleme işlemleriyle ilgili anomali tespiti yapar."""
        now = datetime.now()
        backup_start_time = None

        for line in logs:
            timestamp = self.extract_timestamp(line)
            if timestamp:
                # Küçük/büyük harf duyarsız arama
                for keyword in self.keywords:
                    if keyword.lower() in line.lower():
                        self.event_times[keyword].append(timestamp)
                        
                        if keyword == "Yedekleme baslatildi":
                            backup_start_time = timestamp
                        elif keyword == "Yedekleme tamamlandi" and backup_start_time:
                            time_taken = timestamp - backup_start_time
                            # 1. Yedekleme süresi çok uzun sürüyorsa
                            if time_taken > timedelta(minutes=30):  # 30 dakika
                                self.anomalies.append(f"Yedekleme işlemi çok uzun sürdü: {time_taken}.")
                            backup_start_time = None

        # 2. Yedekleme sırasında beklenmedik kesilme
        if self.last_backup_time and (now - self.last_backup_time) > timedelta(minutes=20):
            self.anomalies.append("Yedekleme işlemi beklenmedik şekilde kesildi veya uzun süre devam etti.")

        # 3. Aynı anda birden fazla yedekleme başlatma
        if len(self.event_times["Yedekleme baslatildi"]) > 2:
            self.anomalies.append("Kısa bir süre içinde birden fazla yedekleme başlatıldı.")

    def write_analysis_to_file(self):
        """Tespit edilen anomalileri analiz dosyasına yazar."""
        if self.anomalies:
            with open(self.analysis_file_path, 'a') as analysis_file:
                analysis_file.write(f"\nTarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                analysis_file.write("Tespit Edilen Anomaliler:\n")
                for anomaly in self.anomalies:
                    analysis_file.write(f"- {anomaly}\n")
                self.anomalies = []  # Anomalileri temizle

    def run_detection(self):
        """Sürekli log dosyasını kontrol eden fonksiyon."""
        while self.running:
            logs = self.read_logs()
            self.detect_anomalies(logs)
            self.write_analysis_to_file()  # Anomalileri dosyaya kaydet
            time.sleep(10)  # 10 saniye arayla kontrol et

    def stop_detection(self):
        """Anomali tespitini durdurur."""
        self.running = False

# Main program
if __name__ == "__main__":
    log_file_path = 'backup_log.txt'  # Log dosyanızın yolu
    analysis_file_path = 'backup_analysis.txt'  # Analiz dosyasının yolu
    detector = BackupAnomalyDetection(log_file_path, analysis_file_path)
    
    # Detection thread başlatılır
    detection_thread = threading.Thread(target=detector.run_detection)
    detection_thread.start()

    try:
        while True:
            time.sleep(1)  # Ana thread, kullanıcı müdahalesi için aktif tutulur
    except KeyboardInterrupt:
        detector.stop_detection()
        detection_thread.join()
        print("Anomali tespiti durduruldu.")
