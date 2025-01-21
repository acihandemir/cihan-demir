import os
import shutil
import logging
from datetime import datetime

# Loglama yapılandırması
def setup_logger(log_file, category):
    logger = logging.getLogger(category)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

# Log dosyasına yazma işlemi
def log_backup_operation(operation_code, status_code, source_dir, backup_size):
    # Yedekleme işlemi log dosyasına kaydedilir
    log_file = "backup_log.txt"  # Yedekleme log dosyası
    logger = setup_logger(log_file, "backup")

    start_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    end_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')

    log_entry = f"Start Time: {start_time}, End Time: {end_time}, Operation Code: {operation_code}, Status Code: {status_code}, Source Dir: {source_dir}, Backup Size: {backup_size} bytes"
    
    logger.info(log_entry)

# Yedekleme işlemi raporlama
def backup_and_log(source_dir, backup_dir):
    operation_code = "backup"
    status_code = "success"
    backup_size = 0  # Yedeklenen veri miktarı

    try:
        # Yedekleme işlemi
        for filename in os.listdir(source_dir):
            source_file = os.path.join(source_dir, filename)
            backup_file = os.path.join(backup_dir, filename)
            
            if os.path.exists(source_file):
                # Dosya kopyalama işlemi
                shutil.copy(source_file, backup_file)
                backup_size += os.path.getsize(source_file)

        # İşlem başarılıysa log kaydı
        log_backup_operation(operation_code, status_code, source_dir, backup_size)

    except Exception as e:
        status_code = "failed"  # Eğer hata olursa işlem başarısız sayılır
        log_backup_operation(operation_code, status_code, source_dir, backup_size)
        print(f"Backup failed: {e}")

# Test için ana fonksiyon
def main():
    source_dir = "C:\\Users\\aciha\\Desktop\\YGI-2\\storage"  # Kaynak dizin
    backup_dir = "C:\\Users\\aciha\\Desktop\\YGI-2\\backups"  # Yedekleme dizini
    
    # Yedekleme işlemini logla
    backup_and_log(source_dir, backup_dir)

if __name__ == "__main__":
    main()
