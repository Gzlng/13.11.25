import socket
import threading
import time
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import sqlite3
import os

class ChatDatabase:
    def __init__(self, db_name="chat_history.db"):
        self.db_name = db_name
        self.init_database()
        
    def init_database(self):
        """Инициализация базы данных и создание таблиц"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Таблица для сообщений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                message_type TEXT NOT NULL,
                from_user TEXT,
                to_user TEXT,
                message_text TEXT NOT NULL,
                is_own INTEGER DEFAULT 0
            )
        ''')
        
        # Таблица для пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                last_seen DATETIME,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def save_message(self, message_type, from_user, to_user, message_text, is_own=False):
        """Сохранение сообщения в базу данных"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (message_type, from_user, to_user, message_text, is_own)
            VALUES (?, ?, ?, ?, ?)
        ''', (message_type, from_user, to_user, message_text, 1 if is_own else 0))
        
        conn.commit()
        conn.close()
        
    def get_message_history(self, limit=100, message_type=None):
        """Получение истории сообщений"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        query = '''
            SELECT timestamp, message_type, from_user, to_user, message_text, is_own
            FROM messages
        '''
        params = []
        
        if message_type:
            query += ' WHERE message_type = ?'
            params.append(message_type)
            
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        messages = cursor.fetchall()
        conn.close()
        
        # Возвращаем в правильном порядке (от старых к новым)
        return list(reversed(messages))
        
    def get_private_conversation(self, other_user_ip, limit=50):
        """Получение истории личной переписки с конкретным пользователем"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, message_type, from_user, to_user, message_text, is_own
            FROM messages
            WHERE (from_user = ? AND to_user = ?) 
               OR (from_user = ? AND to_user = ?)
            ORDER BY timestamp DESC LIMIT ?
        ''', (other_user_ip, 'private', 'private', other_user_ip, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        return list(reversed(messages))
        
    def clear_history(self, days_old=None):
        """Очистка истории сообщений"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        if days_old:
            cursor.execute('''
                DELETE FROM messages 
                WHERE timestamp < datetime('now', ?)
            ''', (f'-{days_old} days',))
        else:
            cursor.execute('DELETE FROM messages')
            
        conn.commit()
        conn.close()

class P2PChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Чат")
        self.root.geometry("800x600")
        
        self.username = socket.gethostbyname(socket.gethostname())
        self.running = True
        
        # Инициализация базы данных
        self.db = ChatDatabase()
        
        # Настройки для группового чата (multicast)
        self.multicast_group = '224.1.1.1'
        self.multicast_port = 5007
        self.multicast_ttl = 1
        self.tcp_port = 5008
        self.known_users = {}  # ip -> {'last_seen': timestamp, 'status': 'online'}
        
        # Улучшенные настройки таймаутов
        self.HEARTBEAT_INTERVAL = 25  # секунд между heartbeat
        self.USER_TIMEOUT = 60  # секунд до отметки как offline
        self.CLEANUP_INTERVAL = 30  # секунд между очистками
        
        self.setup_sockets()
        self.create_widgets()
        self.start_listeners()
        
        # Загрузка истории сообщений
        self.load_message_history()
        
        # Запуск heartbeat
        self.start_heartbeat()
        
    def setup_sockets(self):
        """Инициализация сокетов с улучшенной обработкой ошибок"""
        try:
            # Multicast сокет для группового чата
            self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.multicast_ttl)
            self.multicast_socket.settimeout(0.5)  # Таймаут для неблокирующей работы
            
            # UDP сокет для приема multicast
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind(('', self.multicast_port))
            self.udp_socket.settimeout(0.5)  # Таймаут для неблокирующей работы
            
            # Подписка на multicast группу
            group = socket.inet_aton(self.multicast_group)
            mreq = group + socket.inet_aton('0.0.0.0')
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # TCP сокет для личных сообщений
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.settimeout(0.5)  # Таймаут для accept
            self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_socket.listen(5)
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось инициализировать сокеты: {e}")
            sys.exit(1)
            
    def create_widgets(self):
        """Создание элементов интерфейса"""
        # Основной фрейм
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Настройка весов для растягивания
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Информация о пользователе
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(info_frame, text=f"Ваш IP: {self.username}", 
                 font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        ttk.Button(info_frame, text="Обновить", 
                  command=self.broadcast_online).pack(side=tk.RIGHT)
        
        # Меню для работы с историей
        history_menu = tk.Menu(self.root)
        self.root.config(menu=history_menu)
        
        history_submenu = tk.Menu(history_menu, tearoff=0)
        history_menu.add_cascade(label="История", menu=history_submenu)
        history_submenu.add_command(label="Загрузить историю", command=self.load_message_history)
        history_submenu.add_command(label="Очистить историю", command=self.clear_history_dialog)
        history_submenu.add_separator()
        history_submenu.add_command(label="Показать только групповые", 
                                   command=lambda: self.load_message_history("group"))
        history_submenu.add_command(label="Показать только личные", 
                                   command=lambda: self.load_message_history("private"))
        history_submenu.add_command(label="Показать все", 
                                   command=lambda: self.load_message_history())
        
        # Фрейм с пользователями и чатом
        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(0, weight=1)
        
        # Список пользователей
        users_frame = ttk.LabelFrame(content_frame, text="Онлайн пользователи", padding="5", width=200)
        users_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        users_frame.columnconfigure(0, weight=1)
        users_frame.rowconfigure(0, weight=1)
        
        self.users_listbox = tk.Listbox(users_frame, height=15)
        self.users_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar_users = ttk.Scrollbar(users_frame, orient=tk.VERTICAL, command=self.users_listbox.yview)
        scrollbar_users.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.users_listbox.configure(yscrollcommand=scrollbar_users.set)
        
        # Кнопки для пользователей
        users_buttons_frame = ttk.Frame(users_frame)
        users_buttons_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        ttk.Button(users_buttons_frame, text="Личное сообщение",
                  command=self.send_private_from_list).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(users_buttons_frame, text="История переписки",
                  command=self.show_conversation_history).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Область чата
        chat_frame = ttk.LabelFrame(content_frame, text="Чат", padding="5")
        chat_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        
        self.chat_text = scrolledtext.ScrolledText(chat_frame, height=20, width=60, state=tk.DISABLED)
        self.chat_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Фрейм ввода сообщения
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        input_frame.columnconfigure(0, weight=1)
        
        # Выбор типа сообщения
        type_frame = ttk.Frame(input_frame)
        type_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.message_type = tk.StringVar(value="group")
        ttk.Radiobutton(type_frame, text="Групповое", variable=self.message_type, 
                       value="group").pack(side=tk.LEFT)
        ttk.Radiobutton(type_frame, text="Личное", variable=self.message_type, 
                       value="private").pack(side=tk.LEFT, padx=(20, 0))
        
        # Поле ввода и кнопка отправки
        send_frame = ttk.Frame(input_frame)
        send_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        send_frame.columnconfigure(0, weight=1)
        
        self.message_entry = ttk.Entry(send_frame)
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        ttk.Button(send_frame, text="Отправить", command=self.send_message).grid(row=0, column=1)
        
        # Статус бар
        self.status_var = tk.StringVar(value="Готов к работе")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Обновление списка пользователей
        self.update_users_list()
        
    def send_heartbeat(self):
        """Регулярная отправка heartbeat для поддержания соединения"""
        while self.running:
            try:
                self.broadcast_online()
                time.sleep(self.HEARTBEAT_INTERVAL)
            except Exception as e:
                print(f"Ошибка heartbeat: {e}")
                
    def start_heartbeat(self):
        """Запуск потока heartbeat"""
        heartbeat_thread = threading.Thread(target=self.send_heartbeat)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        
    def send_private_from_list(self):
        """Отправка личного сообщения выбранному пользователю"""
        selection = self.users_listbox.curselection()
        if selection:
            user_data = self.users_listbox.get(selection[0])
            if "(Вы)" in user_data:
                messagebox.showwarning("Предупреждение", "Нельзя отправить сообщение самому себе")
                return
                
            target_ip = user_data.split(" ")[0]  # Извлекаем IP из строки
            self.message_type.set("private")
            self.message_entry.focus()
            self.status_var.set(f"Режим личного сообщения для {target_ip}")
            
    def show_conversation_history(self):
        """Показать историю переписки с выбранным пользователем"""
        selection = self.users_listbox.curselection()
        if selection:
            user_data = self.users_listbox.get(selection[0])
            if "(Вы)" in user_data:
                messagebox.showwarning("Предупреждение", "Нельзя посмотреть историю с самим собой")
                return
                
            target_ip = user_data.split(" ")[0]
            self.load_conversation_history(target_ip)
        else:
            messagebox.showwarning("Предупреждение", "Выберите пользователя для просмотра истории")
            
    def send_message(self):
        """Отправка сообщения"""
        message = self.message_entry.get().strip()
        if not message:
            return
            
        message_type = self.message_type.get()
        
        if message_type == "group":
            self.send_group_message(message)
        else:
            selection = self.users_listbox.curselection()
            if selection:
                user_data = self.users_listbox.get(selection[0])
                if "(Вы)" not in user_data:
                    target_ip = user_data.split(" ")[0]
                    self.send_private_message(target_ip, message)
                    # Сохраняем в базу данных
                    self.db.save_message("private", self.username, target_ip, message, is_own=True)
                    self.add_message_to_chat(f"Вы -> {target_ip}: {message}", "own_private")
                else:
                    messagebox.showwarning("Предупреждение", "Нельзя отправить сообщение самому себе")
                    return
            else:
                messagebox.showwarning("Предупреждение", "Выберите пользователя для личного сообщения")
                return
                
        self.message_entry.delete(0, tk.END)
        
    def send_group_message(self, message):
        """Отправка сообщения в групповой чат"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        data = {
            'type': 'group_message',
            'username': self.username,
            'message': message,
            'timestamp': timestamp
        }
        
        try:
            json_data = json.dumps(data).encode('utf-8')
            self.multicast_socket.sendto(json_data, (self.multicast_group, self.multicast_port))
            # Сохраняем в базу данных
            self.db.save_message("group", self.username, None, message, is_own=True)
        except Exception as e:
            self.status_var.set(f"Ошибка отправки: {e}")
            
    def send_private_message(self, target_ip, message):
        """Отправка личного сообщения"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((target_ip, self.tcp_port))
                
                data = {
                    'type': 'private_message',
                    'from': self.username,
                    'message': message,
                    'timestamp': datetime.now().strftime("%H:%M:%S")
                }
                
                json_data = json.dumps(data).encode('utf-8')
                sock.send(json_data)
                self.status_var.set(f"Личное сообщение отправлено {target_ip}")
                
        except Exception as e:
            self.status_var.set(f"Ошибка отправки: {e}")
            messagebox.showerror("Ошибка", f"Не удалось отправить сообщение {target_ip}: {e}")
            
    def handle_private_connection(self, client_socket, address):
        """Обработка входящих личных сообщений"""
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if data:
                message_data = json.loads(data)
                if message_data['type'] == 'private_message':
                    # Сохраняем в базу данных
                    self.db.save_message("private", message_data['from'], self.username, 
                                       message_data['message'], is_own=False)
                    
                    self.add_message_to_chat(
                        f"{message_data['from']} (личное): {message_data['message']}", 
                        "private"
                    )
                    self.status_var.set(f"Новое личное сообщение от {message_data['from']}")
                    
        except Exception as e:
            print(f"Ошибка при обработке личного сообщения: {e}")
        finally:
            client_socket.close()
            
    def listen_private_messages(self):
        """Прослушивание входящих личных сообщений с улучшенной стабильностью"""
        while self.running:
            try:
                client_socket, address = self.tcp_socket.accept()
                thread = threading.Thread(target=self.handle_private_connection, args=(client_socket, address))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Только если не завершаем работу
                    print(f"Ошибка accept: {e}")
                time.sleep(1)
                
    def listen_group_messages(self):
        """Прослушивание групповых сообщений с улучшенной стабильностью"""
        while self.running:
            try:
                data, address = self.udp_socket.recvfrom(1024)
                message_data = json.loads(data.decode('utf-8'))
                
                if message_data['type'] == 'group_message':
                    # Обновляем список известных пользователей
                    if address[0] != self.username:
                        self.update_user_status(address[0], 'online')
                    
                    # Сохраняем в базу данных
                    self.db.save_message("group", message_data['username'], None, 
                                       message_data['message'], is_own=False)
                    
                    self.add_message_to_chat(
                        f"{message_data['username']}: {message_data['message']}", 
                        "group"
                    )
                    
                elif message_data['type'] == 'user_online':
                    if address[0] != self.username:
                        was_online = address[0] in self.known_users
                        self.update_user_status(address[0], 'online')
                        
                        if not was_online:
                            self.add_system_message(f"Пользователь {address[0]} в сети")
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Только если не завершаем работу
                    print(f"Ошибка приема multicast: {e}")
                    
    def update_user_status(self, user_ip, status):
        """Обновление статуса пользователя"""
        current_time = time.time()
        self.known_users[user_ip] = {
            'last_seen': current_time,
            'status': status
        }
        self.update_users_list()
        
    def add_message_to_chat(self, message, message_type):
        """Добавление сообщения в чат"""
        self.chat_text.config(state=tk.NORMAL)
        
        # Добавляем временную метку
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        self.chat_text.insert(tk.END, formatted_message + "\n", message_type)
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)
        
    def add_system_message(self, message):
        """Добавление системного сообщения"""
        self.add_message_to_chat(f"[Система] {message}", "system")
        
    def broadcast_online(self):
        """Рассылка информации о том, что пользователь онлайн"""
        data = {
            'type': 'user_online',
            'username': self.username
        }
        try:
            json_data = json.dumps(data).encode('utf-8')
            self.multicast_socket.sendto(json_data, (self.multicast_group, self.multicast_port))
        except Exception as e:
            self.status_var.set(f"Ошибка отправки онлайн-статуса: {e}")
            
    def update_users_list(self):
        """Обновление списка пользователей"""
        self.users_listbox.delete(0, tk.END)
        self.users_listbox.insert(tk.END, f"{self.username} (Вы)")
        
        current_time = time.time()
        online_users = []
        
        for user_ip, user_data in self.known_users.items():
            if current_time - user_data['last_seen'] <= self.USER_TIMEOUT:
                online_users.append(user_ip)
            else:
                # Помечаем как отключившегося
                if user_data['status'] == 'online':
                    self.known_users[user_ip]['status'] = 'offline'
                    self.add_system_message(f"Пользователь {user_ip} отключился")
        
        # Сортируем и добавляем онлайн пользователей
        for user_ip in sorted(online_users):
            self.users_listbox.insert(tk.END, f"{user_ip}")
            
    def cleanup_old_users(self):
        """Очистка старых пользователей с улучшенной логикой"""
        while self.running:
            time.sleep(self.CLEANUP_INTERVAL)
            current_time = time.time()
            users_to_remove = []
            
            for user_ip, user_data in self.known_users.items():
                if current_time - user_data['last_seen'] > self.USER_TIMEOUT * 2:  # Удаляем через 2 таймаута
                    users_to_remove.append(user_ip)
                    
            for user_ip in users_to_remove:
                del self.known_users[user_ip]
                self.update_users_list()
                
    def load_message_history(self, message_type=None, limit=100):
        """Загрузка истории сообщений из базы данных"""
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete(1.0, tk.END)
        
        messages = self.db.get_message_history(limit, message_type)
        
        for msg in messages:
            timestamp, msg_type, from_user, to_user, text, is_own = msg
            
            # Форматируем время
            if isinstance(timestamp, str):
                display_time = timestamp.split('.')[0]  # Убираем миллисекунды если есть
            else:
                display_time = timestamp
                
            # Определяем тип сообщения для форматирования
            if msg_type == "group":
                if is_own:
                    display_msg = f"[{display_time}] Вы: {text}"
                    tag = "own_group"
                else:
                    display_msg = f"[{display_time}] {from_user}: {text}"
                    tag = "group"
            else:  # private
                if is_own:
                    display_msg = f"[{display_time}] Вы -> {to_user}: {text}"
                    tag = "own_private"
                else:
                    display_msg = f"[{display_time}] {from_user} (личное): {text}"
                    tag = "private"
                    
            self.chat_text.insert(tk.END, display_msg + "\n", tag)
            
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)
        
    def load_conversation_history(self, other_user_ip, limit=50):
        """Загрузка истории личной переписки"""
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete(1.0, tk.END)
        
        messages = self.db.get_private_conversation(other_user_ip, limit)
        
        if not messages:
            self.chat_text.insert(tk.END, f"История переписки с {other_user_ip} пуста\n", "system")
        else:
            self.chat_text.insert(tk.END, f"=== История переписки с {other_user_ip} ===\n", "system")
            
            for msg in messages:
                timestamp, msg_type, from_user, to_user, text, is_own = msg
                
                # Форматируем время
                if isinstance(timestamp, str):
                    display_time = timestamp.split('.')[0]
                else:
                    display_time = timestamp
                    
                if is_own:
                    display_msg = f"[{display_time}] Вы: {text}"
                    tag = "own_private"
                else:
                    display_msg = f"[{display_time}] {from_user}: {text}"
                    tag = "private"
                    
                self.chat_text.insert(tk.END, display_msg + "\n", tag)
                
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)
        
    def clear_history_dialog(self):
        """Диалог очистки истории"""
        result = messagebox.askyesno(
            "Очистка истории", 
            "Вы уверены, что хотите очистить всю историю сообщений?",
            detail="Это действие нельзя отменить."
        )
        
        if result:
            self.db.clear_history()
            self.chat_text.config(state=tk.NORMAL)
            self.chat_text.delete(1.0, tk.END)
            self.chat_text.insert(tk.END, "История сообщений очищена\n", "system")
            self.chat_text.config(state=tk.DISABLED)
            self.status_var.set("История сообщений очищена")
            
    def start_listeners(self):
        """Запуск потоков прослушивания"""
        # Поток для групповых сообщений
        group_thread = threading.Thread(target=self.listen_group_messages)
        group_thread.daemon = True
        group_thread.start()
        
        # Поток для личных сообщений
        private_thread = threading.Thread(target=self.listen_private_messages)
        private_thread.daemon = True
        private_thread.start()
        
        # Поток для очистки старых пользователей
        cleanup_thread = threading.Thread(target=self.cleanup_old_users)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
    def on_closing(self):
        """Действия при закрытии окна"""
        self.running = False
        time.sleep(0.5)  # Даем время потокам завершиться
        
        try:
            self.udp_socket.close()
            self.multicast_socket.close()
            self.tcp_socket.close()
        except:
            pass
        self.root.destroy()

def main():
    root = tk.Tk()
    app = P2PChatGUI(root)
    
    # Обработка закрытия окна
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Настройка тегов для цветов сообщений
    app.chat_text.tag_config("group", foreground="black")
    app.chat_text.tag_config("private", foreground="blue")
    app.chat_text.tag_config("own_group", foreground="darkgreen")
    app.chat_text.tag_config("own_private", foreground="purple")
    app.chat_text.tag_config("system", foreground="gray")
    
    root.mainloop()

if __name__ == "__main__":
    main()