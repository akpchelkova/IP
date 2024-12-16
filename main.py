import sys
import os
import logging
from scapy.all import sniff, IP, TCP
import tkinter as tk
from tkinter import messagebox
import threading
from collections import Counter
from datetime import datetime, timedelta

# Логирование
logging.basicConfig(
    filename="traffic_monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Список для отслеживания заблокированных IP-адресов
blocked_ips = set()

# Файл для хранения заблокированных IP-адресов
BLOCKED_IP_FILE = "blocked_ips.txt"

# Загрузка заблокированных IP-адресов из файла, если он существует
if os.path.exists(BLOCKED_IP_FILE):
    with open(BLOCKED_IP_FILE, "r") as f:
        for line in f:
            blocked_ips.add(line.strip())

# Множество для отслеживания всех уникальных пакетов
all_packets = set()
recent_ips = Counter()  # Счетчик IP для анализа повторов
last_check_time = datetime.now()
sniffing_active = False  # Флаг для управления началом/остановкой сниффинга
sniff_thread = None  # Поток для сниффинга
fake_traffic_thread = None  # Поток для генерации фейкового трафика

# Обновление списков в GUI
def update_blocked_ips_list():
    blocked_ips_list.delete(0, tk.END)
    for ip in blocked_ips:
        blocked_ips_list.insert(tk.END, ip)

def update_all_packets_list():
    all_packets_list.delete(0, tk.END)
    for packet in all_packets:
        all_packets_list.insert(tk.END, packet)

# Функция для обработки пакетов
def packet_handler(packet):
    global last_check_time

    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport

        # Добавление пакета в список всех пакетов
        packet_summary = f"{ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}"
        all_packets.add(packet_summary)

        # Логика блокировки по повторяющимся IP
        recent_ips[ip_src] += 1
        if datetime.now() - last_check_time > timedelta(seconds=5):
            for ip, count in recent_ips.items():
                if count >= 5 and ip not in blocked_ips:  # Блокируем IP, если он повторился 5 раз
                    block_ip(ip)
            recent_ips.clear()
            last_check_time = datetime.now()

        update_all_packets_list()

# Функция блокировки IP
def block_ip(ip):
    blocked_ips.add(ip)
    with open(BLOCKED_IP_FILE, "a") as f:
        f.write(ip + "\n")
    logging.info(f"IP {ip} заблокирован.")
    update_blocked_ips_list()

# Функция разблокировки IP
def unblock_ip(ip):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        with open(BLOCKED_IP_FILE, "w") as f:
            for blocked_ip in blocked_ips:
                f.write(blocked_ip + "\n")
        logging.info(f"IP {ip} разблокирован.")
        update_blocked_ips_list()
    else:
        messagebox.showwarning("Предупреждение", f"IP {ip} не найден в списке заблокированных.")

# Функция для начала сниффинга
def start_sniffing():
    global sniffing_active
    sniffing_active = True
    sniff(prn=packet_handler, store=False, filter="ip and tcp", stop_filter=lambda x: not sniffing_active)

# Функция для остановки сниффинга
def stop_sniffing():
    global sniffing_active
    sniffing_active = False

# Генерация тестового трафика
def generate_fake_traffic():
    import random
    fake_ips = [f"192.168.1.{i}" for i in range(1, 21)]  # Генерируем 20 IP
    while sniffing_active:
        ip_src = random.choice(fake_ips)
        packet_summary = f"{ip_src}:12345 -> 192.168.0.1:80"
        all_packets.add(packet_summary)
        recent_ips[ip_src] += 1
        if recent_ips[ip_src] >= 5 and ip_src not in blocked_ips:  # Блокируем IP после 5 повторов
            block_ip(ip_src)
        update_all_packets_list()
        threading.Event().wait(1)  # Интервал в 1 секунду между пакетами

# Действия кнопок
def on_start_click():
    global sniff_thread, fake_traffic_thread, sniffing_active
    if not sniffing_active:  # Проверяем, не запущен ли уже анализ
        sniff_thread = threading.Thread(target=start_sniffing)
        sniff_thread.daemon = True
        sniff_thread.start()

        fake_traffic_thread = threading.Thread(target=generate_fake_traffic)
        fake_traffic_thread.daemon = True
        fake_traffic_thread.start()

        messagebox.showinfo("Запуск", "Анализ трафика начат.")
    else:
        messagebox.showwarning("Внимание", "Анализ уже запущен.")

def on_stop_click():
    stop_sniffing()
    messagebox.showinfo("Остановка", "Анализ трафика остановлен.")

def on_unblock_click():
    selected_ip = blocked_ips_list.get(tk.ACTIVE)
    if selected_ip:
        unblock_ip(selected_ip)

def on_exit_click():
    stop_sniffing()
    root.destroy()

# Создание GUI
root = tk.Tk()
root.title("Мониторинг и блокировка трафика")

# Добавление скроллбара для списка всех пакетов
all_packets_frame = tk.Frame(root)
all_packets_frame.pack(pady=10)

all_packets_scrollbar = tk.Scrollbar(all_packets_frame, orient=tk.VERTICAL)
all_packets_list = tk.Listbox(all_packets_frame, width=100, height=20, yscrollcommand=all_packets_scrollbar.set)
all_packets_scrollbar.config(command=all_packets_list.yview)

all_packets_list.pack(side=tk.LEFT, fill=tk.BOTH)
all_packets_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Кнопка "Запустить"
start_button = tk.Button(root, text="Запустить", command=on_start_click)
start_button.pack(pady=5)

# Кнопка "Остановить"
stop_button = tk.Button(root, text="Остановить", command=on_stop_click)
stop_button.pack(pady=5)

# Кнопка "Разблокировать"
unblock_button = tk.Button(root, text="Разблокировать IP", command=on_unblock_click)
unblock_button.pack(pady=5)

# Кнопка "Завершить работу"
exit_button = tk.Button(root, text="Завершить работу", command=on_exit_click)
exit_button.pack(pady=5)

# Добавление скроллбара для списка заблокированных IP
blocked_ips_frame = tk.Frame(root)
blocked_ips_frame.pack(pady=10)

blocked_ips_scrollbar = tk.Scrollbar(blocked_ips_frame, orient=tk.VERTICAL)
blocked_ips_list = tk.Listbox(blocked_ips_frame, width=50, height=10, yscrollcommand=blocked_ips_scrollbar.set)
blocked_ips_scrollbar.config(command=blocked_ips_list.yview)

blocked_ips_list.pack(side=tk.LEFT, fill=tk.BOTH)
blocked_ips_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Запуск GUI
root.mainloop()

