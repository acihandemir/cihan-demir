import os
import shutil
import time
import logging
from datetime import datetime
from multiprocessing import Process

# Loglama yapılandırması
def setup_logger(log_file, category):
    logger = logging.getLogger(category)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

# Kullanıcıların klasörlerini yedekleme işlemi
def backup_user_folders(source_dir, backup_dir):
    logger = setup_logger('backup_log.txt', 'backup')
    logger.info("Backup started.")

    # Zaman damgası oluştur
    timestamp = datetime.now().strftime('%d-%m-%Y_%H-%M-%S')
    timestamp_backup_dir = os.path.join(backup_dir, timestamp)

    # Yedekleme için yeni klasör oluştur
    if not os.path.exists(timestamp_backup_dir):
        os.makedirs(timestamp_backup_dir)

    # Kaynak dizindeki kullanıcı klasörlerini bul
    for user_folder in os.listdir(source_dir):
        user_folder_path = os.path.join(source_dir, user_folder)

        # Eğer bu bir dizinse (yani kullanıcı klasörü ise)
        if os.path.isdir(user_folder_path):
            backup_user_folder(user_folder_path, os.path.join(timestamp_backup_dir, user_folder), logger)

    logger.info("Backup completed.")

# Tek bir kullanıcının klasörünü yedekleme
def backup_user_folder(user_folder_path, backup_user_folder_path, logger):
    logger.info(f"Backing up user folder: {user_folder_path}")

    # Kullanıcı klasörünü yedekleme işlemi
    if not os.path.exists(backup_user_folder_path):
        os.makedirs(backup_user_folder_path)  # Yedek klasörü yoksa oluştur

    for filename in os.listdir(user_folder_path):
        source_file = os.path.join(user_folder_path, filename)
        backup_file = os.path.join(backup_user_folder_path, filename)

        # Eğer yedekleme yapılmamışsa veya kaynak dosya daha yeni ise
        if not os.path.exists(backup_file) or os.path.getmtime(source_file) > os.path.getmtime(backup_file):
            shutil.copy(source_file, backup_file)
            logger.info(f"File {filename} backed up to {backup_user_folder_path}.")

# Yedekleme işlemini sürekli olarak belirli aralıklarla başlatma
def periodic_backup(source_dir, backup_dir, interval_seconds):
    while True:
        backup_user_folders(source_dir, backup_dir)  # Yedekleme işlemini yap
        time.sleep(interval_seconds)  # Belirtilen periyotta bekle

# Ana fonksiyon
def main():
    source_dir = "C:\\Users\\aciha\\Desktop\\YGI-2\\storage"  # Kullanıcıların bulunduğu ana dizin
    backup_dir = "C:\\Users\\aciha\\Desktop\\YGI-2\\backups"  # Yedekleme yapılacak ana dizin
    backup_interval = 5  # 1 saat (3600 saniye)

    # Yedekleme işlemini başlatan multiprocessing sürecini oluştur
    backup_process = Process(target=periodic_backup, args=(source_dir, backup_dir, backup_interval))
    backup_process.start()

    # Program sürekli çalışmaya devam eder
    try:
        while True:
            time.sleep(1)  # Ana döngüde programın durmasını engellemek için
    except KeyboardInterrupt:
        print("Program terminated.")
        backup_process.terminate()  # Süreci sonlandır

if __name__ == "__main__":
    main()
