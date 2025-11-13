import socket
import threading
import struct
import time
import hashlib
import sqlite3
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import select
import queue

class DatabaseManager:
    def __init__(self):
        self.init_database()
    
    def init_database(self):
        """Инициализация базы данных"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        # Таблица пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица контактов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                contact_username TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, contact_username)
            )
        ''')
        
        # Таблица сообщений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message_type TEXT NOT NULL,
                message_text TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Таблица групповых чатов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                creator TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица участников групповых чатов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                username TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES group_chats (id),
                UNIQUE(group_id, username)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def register_user(self, username, password):
        """Регистрация нового пользователя"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def authenticate_user(self, username, password):
        """Аутентификация пользователя"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute(
            'SELECT id FROM users WHERE username = ? AND password_hash = ?',
            (username, password_hash)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def add_contact(self, username, contact_username):
        """Добавление контакта"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        # Проверяем существование пользователя
        cursor.execute('SELECT id FROM users WHERE username = ?', (contact_username,))
        if not cursor.fetchone():
            conn.close()
            return False
        
        try:
            cursor.execute(
                'INSERT INTO contacts (user_id, contact_username) VALUES ((SELECT id FROM users WHERE username = ?), ?)',
                (username, contact_username)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def create_group_chat(self, name, creator):
        """Создание группового чата"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO group_chats (name, creator) VALUES (?, ?)',
                (name, creator)
            )
            group_id = cursor.lastrowid
            
            # Добавляем создателя в участники
            cursor.execute(
                'INSERT INTO group_members (group_id, username) VALUES (?, ?)',
                (group_id, creator)
            )
            
            conn.commit()
            conn.close()
            return group_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    def add_user_to_group(self, group_id, username):
        """Добавление пользователя в групповой чат"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO group_members (group_id, username) VALUES (?, ?)',
                (group_id, username)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def get_user_groups(self, username):
        """Получение групповых чатов пользователя"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT gc.id, gc.name, gc.creator 
            FROM group_chats gc
            JOIN group_members gm ON gc.id = gm.group_id
            WHERE gm.username = ?
            ORDER BY gc.name
        ''', (username,))
        
        groups = [{'id': row[0], 'name': row[1], 'creator': row[2]} for row in cursor.fetchall()]
        conn.close()
        
        return groups
    
    def get_contacts(self, username):
        """Получение списка контактов"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT contact_username FROM contacts 
            WHERE user_id = (SELECT id FROM users WHERE username = ?)
            ORDER BY contact_username
        ''', (username,))
        
        contacts = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return contacts
    
    def save_message(self, sender, receiver, message_type, message_text):
        """Сохранение сообщения в базу данных"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (sender, receiver, message_type, message_text)
            VALUES (?, ?, ?, ?)
        ''', (sender, receiver, message_type, message_text))
        
        conn.commit()
        conn.close()
    
    def get_message_history(self, user1, user2, message_type='private', limit=1000):
        """Получение истории сообщений"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        if message_type == 'group':
            cursor.execute('''
                SELECT sender, message_text, timestamp 
                FROM messages 
                WHERE receiver = ? AND message_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (user2, message_type, limit))
        else:
            cursor.execute('''
                SELECT sender, message_text, timestamp 
                FROM messages 
                WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
                AND message_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (user1, user2, user2, user1, message_type, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        # Возвращаем в правильном порядке (от старых к новым)
        return list(reversed(messages))
    
    def get_all_messages(self, username, limit=500):
        """Получение всех сообщений пользователя"""
        conn = sqlite3.connect('messenger.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT sender, receiver, message_type, message_text, timestamp 
            FROM messages 
            WHERE sender = ? OR receiver = ? OR receiver IN (
                SELECT name FROM group_chats WHERE id IN (
                    SELECT group_id FROM group_members WHERE username = ?
                )
            )
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (username, username, username, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        return list(reversed(messages))

class MulticastMessenger:
    def __init__(self, username, multicast_group='224.1.1.1', port=5007):
        self.username = username
        self.multicast_group = multicast_group
        self.port = port
        self.running = True
        self.contacts = {}
        self.groups = {}
        
        # База данных
        self.db = DatabaseManager()
        
        # Очередь для сообщений GUI
        self.message_queue = queue.Queue()
        
        # Multicast сокет для группового чата
        self.multicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.multicast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.multicast_sock.settimeout(1.0)
        self.join_multicast_group()
        
        # TCP сервер для личных сообщений
        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_server.settimeout(1.0)
        self.tcp_server.bind(('0.0.0.0', 0))
        self.tcp_port = self.tcp_server.getsockname()[1]
        self.tcp_server.listen(5)
        
        # Клиентские TCP соединения
        self.client_sockets = []
        
        # Загрузка контактов и групп
        self.load_contacts()
        self.load_groups()
        
    def join_multicast_group(self):
        """Присоединение к multicast группе"""
        try:
            group = socket.inet_aton(self.multicast_group)
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.multicast_sock.bind(('', self.port))
        except Exception as e:
            print(f"Multicast error: {e}")
    
    def load_contacts(self):
        """Загрузка контактов из базы данных"""
        contacts = self.db.get_contacts(self.username)
        for contact in contacts:
            self.contacts[contact] = {'online': False, 'ip': None, 'port': None}
    
    def load_groups(self):
        """Загрузка групповых чатов"""
        groups = self.db.get_user_groups(self.username)
        for group in groups:
            self.groups[f"GROUP_{group['id']}"] = {
                'name': group['name'],
                'creator': group['creator'],
                'online': True  # Группы всегда онлайн
            }
    
    def broadcast_presence(self):
        """Рассылка информации о своем присутствии"""
        while self.running:
            try:
                presence_msg = {
                    'type': 'presence',
                    'username': self.username,
                    'port': self.tcp_port,
                    'action': 'online'
                }
                
                self.multicast_sock.sendto(
                    json.dumps(presence_msg).encode('utf-8'),
                    (self.multicast_group, self.port)
                )
            except Exception as e:
                print(f"Presence broadcast error: {e}")
            
            time.sleep(10)
    
    def listen_multicast(self):
        """Прослушивание multicast сообщений"""
        while self.running:
            try:
                data, addr = self.multicast_sock.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                
                if message['type'] == 'presence':
                    self.handle_presence(message, addr[0])
                elif message['type'] == 'group_message':
                    self.handle_group_message(message)
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Multicast listen error: {e}")
    
    def handle_presence(self, message, ip):
        """Обработка сообщений о присутствии"""
        username = message['username']
        
        if username != self.username and username in self.contacts:
            self.contacts[username]['online'] = (message['action'] == 'online')
            self.contacts[username]['ip'] = ip
            self.contacts[username]['port'] = message['port']
            
            self.message_queue.put(('update_contacts', None))
    
    def handle_group_message(self, message):
        """Обработка групповых сообщений"""
        if message['sender'] != self.username:
            # Сохраняем в базу данных
            self.db.save_message(
                message['sender'], 
                message['group_id'], 
                'group', 
                message['text']
            )
            
            # Отправляем в очередь для GUI
            self.message_queue.put(('group_message', message))
    
    def send_group_message(self, group_id, text):
        """Отправка группового сообщения"""
        try:
            message = {
                'type': 'group_message',
                'sender': self.username,
                'group_id': group_id,
                'text': text,
                'timestamp': datetime.now().isoformat()
            }
            
            self.multicast_sock.sendto(
                json.dumps(message).encode('utf-8'),
                (self.multicast_group, self.port)
            )
            
            # Сохраняем свое сообщение
            self.db.save_message(self.username, group_id, 'group', text)
            return True
        except Exception as e:
            print(f"Send group message error: {e}")
            return False
    
    def listen_tcp(self):
        """Прослушивание TCP соединений для личных сообщений"""
        while self.running:
            try:
                read_sockets = [self.tcp_server] + self.client_sockets
                read_sockets, _, _ = select.select(read_sockets, [], [], 1.0)
                
                for sock in read_sockets:
                    if sock == self.tcp_server:
                        try:
                            client_socket, addr = self.tcp_server.accept()
                            client_socket.settimeout(1.0)
                            self.client_sockets.append(client_socket)
                        except socket.timeout:
                            continue
                    else:
                        try:
                            data = sock.recv(1024)
                            if data:
                                message = json.loads(data.decode('utf-8'))
                                self.handle_private_message(message)
                            else:
                                sock.close()
                                if sock in self.client_sockets:
                                    self.client_sockets.remove(sock)
                        except socket.timeout:
                            continue
                        except:
                            sock.close()
                            if sock in self.client_sockets:
                                self.client_sockets.remove(sock)
                            
            except Exception as e:
                if self.running:
                    print(f"TCP listen error: {e}")
    
    def handle_private_message(self, message):
        """Обработка личных сообщений"""
        if message['type'] == 'private_message':
            # Сохраняем в базу данных
            self.db.save_message(
                message['sender'],
                message['receiver'],
                'private',
                message['text']
            )
            
            # Отправляем в очередь для GUI
            self.message_queue.put(('private_message', message))
    
    def send_private_message(self, receiver, text):
        """Отправка личного сообщения"""
        # Всегда сохраняем сообщение в БД, даже если пользователь оффлайн
        self.db.save_message(self.username, receiver, 'private', text)
        
        if receiver in self.contacts and self.contacts[receiver]['online']:
            try:
                message = {
                    'type': 'private_message',
                    'sender': self.username,
                    'receiver': receiver,
                    'text': text,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Создаем отдельный поток для отправки
                thread = threading.Thread(
                    target=self._send_private_message_thread,
                    args=(receiver, message)
                )
                thread.daemon = True
                thread.start()
                return True
            except Exception as e:
                print(f"Send private message error: {e}")
                return False
        return True  # Возвращаем True, так как сообщение сохранено
    
    def _send_private_message_thread(self, receiver, message):
        """Поток для отправки личного сообщения"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            
            contact_ip = self.contacts[receiver]['ip']
            contact_port = self.contacts[receiver]['port']
            
            sock.connect((contact_ip, contact_port))
            sock.send(json.dumps(message).encode('utf-8'))
            sock.close()
            
        except socket.timeout:
            print(f"Timeout sending message to {receiver}")
            self.contacts[receiver]['online'] = False
            self.message_queue.put(('update_contacts', None))
        except Exception as e:
            print(f"Error sending to {receiver}: {e}")
            self.contacts[receiver]['online'] = False
            self.message_queue.put(('update_contacts', None))
    
    def add_contact(self, contact_username):
        """Добавление контакта"""
        if contact_username != self.username and self.db.add_contact(self.username, contact_username):
            self.contacts[contact_username] = {'online': False, 'ip': None, 'port': None}
            self.message_queue.put(('update_contacts', None))
            return True
        return False
    
    def create_group(self, group_name):
        """Создание группового чата"""
        group_id = self.db.create_group_chat(group_name, self.username)
        if group_id:
            self.load_groups()  # Перезагружаем группы
            self.message_queue.put(('update_groups', None))
            return group_id
        return None
    
    def add_user_to_group(self, group_id, username):
        """Добавление пользователя в группу"""
        return self.db.add_user_to_group(group_id, username)
    
    def get_all_messages(self, limit=500):
        """Получение всех сообщений пользователя"""
        return self.db.get_all_messages(self.username, limit)
    
    def process_message_queue(self):
        """Обработка очереди сообщений для GUI"""
        try:
            while True:
                msg_type, message = self.message_queue.get_nowait()
                
                if msg_type == 'update_contacts' and hasattr(self, 'update_contacts_callback'):
                    self.update_contacts_callback()
                elif msg_type == 'update_groups' and hasattr(self, 'update_groups_callback'):
                    self.update_groups_callback()
                elif msg_type == 'group_message' and hasattr(self, 'group_message_callback'):
                    self.group_message_callback(message)
                elif msg_type == 'private_message' and hasattr(self, 'private_message_callback'):
                    self.private_message_callback(message)
                    
        except queue.Empty:
            pass
    
    def start(self):
        """Запуск всех потоков"""
        threads = [
            threading.Thread(target=self.listen_multicast),
            threading.Thread(target=self.listen_tcp),
            threading.Thread(target=self.broadcast_presence)
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
    
    def stop(self):
        """Остановка мессенджера"""
        self.running = False
        
        try:
            presence_msg = {
                'type': 'presence',
                'username': self.username,
                'port': self.tcp_port,
                'action': 'offline'
            }
            
            self.multicast_sock.sendto(
                json.dumps(presence_msg).encode('utf-8'),
                (self.multicast_group, self.port)
            )
        except:
            pass
        
        try:
            self.multicast_sock.close()
        except:
            pass
        
        try:
            self.tcp_server.close()
        except:
            pass
        
        for sock in self.client_sockets:
            try:
                sock.close()
            except:
                pass

class MessengerGUI:
    def __init__(self, root, messenger):
        self.root = root
        self.messenger = messenger
        self.current_chat = 'MAIN_GROUP'
        self.current_chat_type = 'group'  # 'group' или 'private'
        
        # Настройка callback'ов
        self.messenger.group_message_callback = self.handle_group_message
        self.messenger.private_message_callback = self.handle_private_message
        self.messenger.update_contacts_callback = self.update_contacts_list
        self.messenger.update_groups_callback = self.update_groups_list
        
        self.setup_ui()
        self.load_chat_history()
        
        # Запуск обработки очереди сообщений
        self.process_queue()
    
    def setup_ui(self):
        """Настройка графического интерфейса в красных тонах"""
        self.root.title(f"🔥 Scarlet Messenger - {self.messenger.username}")
        self.root.geometry("1200x800")  # Увеличенный размер
        self.root.configure(bg='#2c0c0c')
        
        # Разрешаем изменение размера окна
        self.root.minsize(1000, 700)
        
        # Стиль для элементов
        style = ttk.Style()
        style.configure('Red.TFrame', background='#3d1515')
        style.configure('Red.TButton', background='#c41e3a', foreground='white')
        style.map('Red.TButton', background=[('active', '#a61a32')])
        
        # Основной фрейм
        main_frame = ttk.Frame(self.root, style='Red.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Левая панель - контакты и группы
        left_frame = ttk.Frame(main_frame, width=300, style='Red.TFrame')  # Увеличена ширина
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left_frame.pack_propagate(False)
        
        # Заголовок
        header = tk.Label(left_frame, text="🔥 Scarlet Messenger", 
                         font=('Arial', 16, 'bold'), bg='#c41e3a', fg='white',
                         pady=15, relief='raised', bd=2)
        header.pack(fill=tk.X)
        
        # Информация о пользователе
        user_info = tk.Label(left_frame, text=f"👤 {self.messenger.username}", 
                           font=('Arial', 12, 'bold'), bg='#3d1515', fg='#ff6b6b',
                           pady=8)
        user_info.pack(fill=tk.X)
        
        # Панель управления
        control_frame = ttk.Frame(left_frame, style='Red.TFrame')
        control_frame.pack(fill=tk.X, pady=15)
        
        add_contact_btn = tk.Button(control_frame, text="👥 Добавить контакт",
                                  command=self.add_contact_dialog,
                                  bg='#e74c3c', fg='white', font=('Arial', 11, 'bold'),
                                  relief='raised', bd=2, padx=15, pady=10,
                                  cursor='hand2')
        add_contact_btn.pack(fill=tk.X, pady=(0, 8))
        
        create_group_btn = tk.Button(control_frame, text="🆕 Создать группу",
                                   command=self.create_group_dialog,
                                   bg='#d35400', fg='white', font=('Arial', 11, 'bold'),
                                   relief='raised', bd=2, padx=15, pady=10,
                                   cursor='hand2')
        create_group_btn.pack(fill=tk.X, pady=(0, 8))
        
        history_btn = tk.Button(control_frame, text="📜 История сообщений",
                              command=self.show_message_history,
                              bg='#c0392b', fg='white', font=('Arial', 11, 'bold'),
                              relief='raised', bd=2, padx=15, pady=10,
                              cursor='hand2')
        history_btn.pack(fill=tk.X)
        
        # Разделитель
        separator = tk.Frame(left_frame, height=3, bg='#c41e3a')
        separator.pack(fill=tk.X, pady=15)
        
        # Заголовок списка чатов
        chats_label = tk.Label(left_frame, text="💬 Мои чаты", 
                             font=('Arial', 13, 'bold'), bg='#3d1515', fg='#ff9999',
                             pady=8)
        chats_label.pack(fill=tk.X)
        
        # Список чатов
        self.chats_listbox = tk.Listbox(left_frame, font=('Arial', 12),
                                       bg='#4a1a1a', fg='#ffcccc', 
                                       selectbackground='#c41e3a',
                                       selectforeground='white',
                                       borderwidth=2, relief='sunken',
                                       highlightthickness=0)
        self.chats_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.chats_listbox.bind('<<ListboxSelect>>', self.on_chat_select)
        
        # Обновляем списки
        self.update_chats_list()
        
        # Правая панель - чат
        right_frame = ttk.Frame(main_frame, style='Red.TFrame')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Заголовок чата
        self.chat_header = tk.Label(right_frame, text="💬 Основной чат", 
                                  font=('Arial', 14, 'bold'), bg='#c41e3a', fg='white',
                                  pady=12, relief='raised', bd=2)
        self.chat_header.pack(fill=tk.X)
        
        # Область сообщений
        messages_frame = ttk.Frame(right_frame, style='Red.TFrame')
        messages_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 15))
        
        self.messages_text = scrolledtext.ScrolledText(
            messages_frame, 
            wrap=tk.WORD,
            font=('Arial', 12),
            bg='#2c0c0c',
            fg='#ffcccc',
            padx=20,
            pady=20,
            state=tk.DISABLED,
            borderwidth=2,
            relief='sunken',
            highlightthickness=0
        )
        self.messages_text.pack(fill=tk.BOTH, expand=True)
        
        # Настройка тегов для сообщений
        self.messages_text.tag_config("own", foreground="#ff6b6b", justify=tk.RIGHT, 
                                    font=('Arial', 12, 'bold'))
        self.messages_text.tag_config("other", foreground="#ff9999", justify=tk.LEFT,
                                    font=('Arial', 12))
        self.messages_text.tag_config("system", foreground="#ffd700", justify=tk.CENTER,
                                    font=('Arial', 11, 'italic'))
        
        # Фрейм ввода сообщения
        input_frame = ttk.Frame(right_frame, style='Red.TFrame')
        input_frame.pack(fill=tk.X)
        
        # Метка для поля ввода
        input_label = tk.Label(input_frame, text="Введите сообщение:", 
                             font=('Arial', 11, 'bold'), bg='#3d1515', fg='#ff9999')
        input_label.pack(anchor='w', pady=(0, 5))
        
        self.message_entry = tk.Text(
            input_frame,
            height=4,
            font=('Arial', 12),
            wrap=tk.WORD,
            bg='#4a1a1a',
            fg='#ffcccc',
            insertbackground='#ff6b6b',
            relief='sunken',
            borderwidth=2,
            padx=15,
            pady=12
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        self.message_entry.bind('<Return>', self.send_message_enter)
        self.message_entry.bind('<Shift-Return>', self.insert_newline)
        
        # Кнопка отправки
        send_button = tk.Button(
            input_frame,
            text="🚀\nОтправить",
            command=self.send_message,
            bg='#c41e3a',
            fg='white',
            font=('Arial', 12, 'bold'),
            relief='raised',
            bd=3,
            padx=20,
            pady=15,
            cursor='hand2'
        )
        send_button.pack(side=tk.RIGHT)
        
        # Счетчик символов
        self.char_count_label = tk.Label(input_frame, text="0/1000", 
                                       font=('Arial', 10), bg='#3d1515', fg='#ff9999')
        self.char_count_label.pack(side=tk.BOTTOM, anchor='e', pady=(5, 0))
        
        # Привязываем отслеживание ввода символов
        self.message_entry.bind('<KeyRelease>', self.update_char_count)
        
        self.message_entry.focus_set()
        self.update_char_count()
    
    def update_char_count(self, event=None):
        """Обновление счетчика символов"""
        text = self.message_entry.get('1.0', 'end-1c')
        count = len(text)
        self.char_count_label.config(text=f"{count}/1000")
        
        # Меняем цвет при приближении к лимиту
        if count > 900:
            self.char_count_label.config(fg='#ff6b6b', font=('Arial', 10, 'bold'))
        else:
            self.char_count_label.config(fg='#ff9999', font=('Arial', 10))
    
    def insert_newline(self, event):
        """Вставка новой строки при Shift+Enter"""
        self.message_entry.insert(tk.INSERT, '\n')
        self.update_char_count()
        return 'break'
    
    def send_message_enter(self, event):
        """Отправка сообщения по Enter"""
        if event.state == 0:  # Простой Enter без модификаторов
            self.send_message()
            return 'break'
        return None
    
    def process_queue(self):
        """Обработка очереди сообщений"""
        self.messenger.process_message_queue()
        self.root.after(100, self.process_queue)
    
    def update_chats_list(self):
        """Обновление списка чатов"""
        self.chats_listbox.delete(0, tk.END)
        
        # Основной групповой чат
        self.chats_listbox.insert(tk.END, "🔥 Основной чат")
        
        # Групповые чаты
        for group_id, group_info in self.messenger.groups.items():
            status = "🟢" if group_info['online'] else "⚫"
            self.chats_listbox.insert(tk.END, f"👥 {group_info['name']} {status}")
        
        # Личные чаты
        for contact, info in self.messenger.contacts.items():
            status = "🟢" if info['online'] else "⚫"
            self.chats_listbox.insert(tk.END, f"👤 {contact} {status}")
    
    def update_contacts_list(self):
        """Обновление списка контактов"""
        self.update_chats_list()
    
    def update_groups_list(self):
        """Обновление списка групп"""
        self.update_chats_list()
    
    def on_chat_select(self, event):
        """Обработка выбора чата"""
        selection = self.chats_listbox.curselection()
        if selection:
            index = selection[0]
            chat_text = self.chats_listbox.get(index)
            
            if chat_text.startswith("🔥"):
                self.current_chat = 'MAIN_GROUP'
                self.current_chat_type = 'group'
                self.chat_header.config(text="🔥 Основной чат")
            elif chat_text.startswith("👥"):
                # Групповой чат
                group_name = chat_text[2:].split(' 🟢')[0].split(' ⚫')[0]
                for group_id, info in self.messenger.groups.items():
                    if info['name'] == group_name:
                        self.current_chat = group_id
                        self.current_chat_type = 'group'
                        self.chat_header.config(text=f"👥 {group_name}")
                        break
            elif chat_text.startswith("👤"):
                # Личный чат
                contact = chat_text[2:].split(' 🟢')[0].split(' ⚫')[0]
                self.current_chat = contact
                self.current_chat_type = 'private'
                status = "🟢" if self.messenger.contacts[contact]['online'] else "⚫"
                self.chat_header.config(text=f"👤 {contact} {status}")
            
            self.load_chat_history()
    
    def load_chat_history(self):
        """Загрузка истории текущего чата"""
        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.delete('1.0', tk.END)
        
        if self.current_chat_type == 'group':
            if self.current_chat == 'MAIN_GROUP':
                # Для основного чата показываем системное сообщение
                self.messages_text.insert(tk.END, "Добро пожаловать в основной групповой чат!\n", "system")
            else:
                # Для других групп загружаем историю
                messages = self.messenger.db.get_message_history(
                    self.messenger.username, 
                    self.current_chat, 
                    'group'
                )
                for sender, text, timestamp in messages:
                    self.display_message(sender, text, timestamp, 'group')
        else:
            # Личный чат
            messages = self.messenger.db.get_message_history(
                self.messenger.username, 
                self.current_chat, 
                'private'
            )
            for sender, text, timestamp in messages:
                self.display_message(sender, text, timestamp, 'private')
        
        self.messages_text.config(state=tk.DISABLED)
        self.messages_text.see(tk.END)
    
    def display_message(self, sender, text, timestamp, msg_type):
        """Отображение сообщения в чате"""
        self.messages_text.config(state=tk.NORMAL)
        
        try:
            time_obj = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            time_str = time_obj.strftime('%H:%M')
        except:
            time_str = timestamp
        
        if sender == self.messenger.username:
            tag = "own"
            prefix = f"[{time_str}] Вы: "
        else:
            tag = "other"
            prefix = f"[{time_str}] {sender}: "
        
        self.messages_text.insert(tk.END, prefix, tag)
        self.messages_text.insert(tk.END, f"{text}\n\n", tag)
        self.messages_text.config(state=tk.DISABLED)
        self.messages_text.see(tk.END)
    
    def handle_group_message(self, message):
        """Обработка входящего группового сообщения"""
        if self.current_chat_type == 'group' and self.current_chat == message['group_id']:
            self.display_message(message['sender'], message['text'], message['timestamp'], 'group')
    
    def handle_private_message(self, message):
        """Обработка входящего личного сообщения"""
        if self.current_chat_type == 'private' and self.current_chat == message['sender']:
            self.display_message(message['sender'], message['text'], message['timestamp'], 'private')
    
    def send_message(self):
        """Отправка сообщения"""
        text = self.message_entry.get('1.0', 'end-1c').strip()
        if not text:
            return
        
        if len(text) > 1000:
            messagebox.showwarning("Слишком длинное сообщение", "Сообщение не должно превышать 1000 символов")
            return
        
        # Очищаем поле ввода
        self.message_entry.delete('1.0', tk.END)
        self.update_char_count()
        
        if self.current_chat_type == 'group':
            if self.current_chat == 'MAIN_GROUP':
                # Отправка в основной чат через multicast
                success = self.messenger.send_group_message('MAIN_GROUP', text)
            else:
                # Отправка в групповой чат
                success = self.messenger.send_group_message(self.current_chat, text)
        else:
            # Отправка личного сообщения
            success = self.messenger.send_private_message(self.current_chat, text)
        
        if success:
            # Немедленно отображаем свое сообщение
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.display_message(self.messenger.username, text, timestamp, 
                               'group' if self.current_chat_type == 'group' else 'private')
        else:
            messagebox.showerror("Ошибка", "Не удалось отправить сообщение")
    
    def add_contact_dialog(self):
        """Диалог добавления контакта"""
        contact_username = simpledialog.askstring("Добавить контакт", "Введите имя пользователя:")
        if contact_username:
            if self.messenger.add_contact(contact_username):
                messagebox.showinfo("Успех", f"Контакт {contact_username} добавлен")
            else:
                messagebox.showerror("Ошибка", "Не удалось добавить контакт")
    
    def create_group_dialog(self):
        """Диалог создания группы"""
        group_name = simpledialog.askstring("Создать группу", "Введите название группы:")
        if group_name:
            group_id = self.messenger.create_group(group_name)
            if group_id:
                messagebox.showinfo("Успех", f"Группа '{group_name}' создана")
            else:
                messagebox.showerror("Ошибка", "Не удалось создать группу")
    
    def show_message_history(self):
        """Показ истории всех сообщений"""
        history_window = tk.Toplevel(self.root)
        history_window.title("📜 История сообщений")
        history_window.geometry("900x700")  # Увеличенный размер
        history_window.configure(bg='#2c0c0c')
        history_window.minsize(800, 600)  # Минимальный размер
        
        # Заголовок
        header = tk.Label(history_window, text="📜 Полная история сообщений", 
                         font=('Arial', 16, 'bold'), bg='#c41e3a', fg='white',
                         pady=15)
        header.pack(fill=tk.X)
        
        # Область истории
        history_text = scrolledtext.ScrolledText(
            history_window,
            wrap=tk.WORD,
            font=('Arial', 11),
            bg='#2c0c0c',
            fg='#ffcccc',
            padx=20,
            pady=20,
            state=tk.NORMAL
        )
        history_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Загрузка истории сообщений
        messages = self.messenger.get_all_messages(1000)
        history_text.insert(tk.END, "=== ПОЛНАЯ ИСТОРИЯ СООБЩЕНИЙ ===\n\n", "system")
        
        for sender, receiver, msg_type, text, timestamp in messages:
            msg_type_str = "Группа" if msg_type == 'group' else "Личное"
            time_str = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').strftime('%d.%m %H:%M')
            
            if sender == self.messenger.username:
                prefix = "📤 Вы ->"
                tag = "own"
            else:
                prefix = f"📥 {sender} ->"
                tag = "other"
            
            history_text.insert(tk.END, 
                              f"[{time_str}] {prefix} {receiver} ({msg_type_str}): {text}\n", 
                              tag)
        
        history_text.config(state=tk.DISABLED)
        
        # Кнопка закрытия
        close_btn = tk.Button(history_window, text="Закрыть", 
                            command=history_window.destroy,
                            bg='#c41e3a', fg='white', font=('Arial', 12, 'bold'),
                            padx=30, pady=10)
        close_btn.pack(pady=15)

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("🔥 Scarlet Messenger - Вход")
        self.root.geometry("500x400")  # Увеличенный размер
        self.root.configure(bg='#2c0c0c')
        self.root.resizable(True, True)  # Разрешаем изменение размера
        self.root.minsize(450, 350)  # Минимальный размер
        
        self.db = DatabaseManager()
        self.setup_ui()
    
    def setup_ui(self):
        """Настройка интерфейса входа"""
        # Основной фрейм
        main_frame = tk.Frame(self.root, bg='#2c0c0c', padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Заголовок
        header = tk.Label(main_frame, text="🔥 Scarlet Messenger", 
                         font=('Arial', 22, 'bold'), bg='#2c0c0c', fg='#c41e3a',
                         pady=25)
        header.pack(fill=tk.X)
        
        # Подзаголовок
        subheader = tk.Label(main_frame, text="Войдите в систему", 
                           font=('Arial', 16), bg='#2c0c0c', fg='#ff9999',
                           pady=15)
        subheader.pack(fill=tk.X)
        
        # Фрейм для формы
        form_frame = tk.Frame(main_frame, bg='#2c0c0c', pady=25)
        form_frame.pack(fill=tk.X)
        
        # Поле имени пользователя
        tk.Label(form_frame, text="Имя пользователя:", 
                font=('Arial', 12, 'bold'), bg='#2c0c0c', fg='#ff9999',
                anchor='w').pack(fill=tk.X, pady=(0, 8))
        
        self.username_entry = tk.Entry(form_frame, font=('Arial', 14),
                                     bg='#4a1a1a', fg='#ffcccc', 
                                     insertbackground='#ff6b6b',
                                     relief='sunken', borderwidth=2,
                                     width=30)
        self.username_entry.pack(fill=tk.X, pady=(0, 20))
        self.username_entry.focus_set()
        
        # Поле пароля
        tk.Label(form_frame, text="Пароль:", 
                font=('Arial', 12, 'bold'), bg='#2c0c0c', fg='#ff9999',
                anchor='w').pack(fill=tk.X, pady=(0, 8))
        
        self.password_entry = tk.Entry(form_frame, font=('Arial', 14),
                                     show='*', bg='#4a1a1a', fg='#ffcccc',
                                     insertbackground='#ff6b6b',
                                     relief='sunken', borderwidth=2,
                                     width=30)
        self.password_entry.pack(fill=tk.X, pady=(0, 25))
        
        # Привязываем Enter к входу
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus_set())
        self.password_entry.bind('<Return>', lambda e: self.login())
        
        # Фрейм для кнопок
        button_frame = tk.Frame(main_frame, bg='#2c0c0c')
        button_frame.pack(fill=tk.X, pady=20)
        
        # Кнопка входа
        login_btn = tk.Button(button_frame, text="Войти", 
                            command=self.login,
                            bg='#c41e3a', fg='white', font=('Arial', 14, 'bold'),
                            relief='raised', bd=2, padx=40, pady=12,
                            cursor='hand2')
        login_btn.pack(side=tk.LEFT, padx=(0, 15))
        
        # Кнопка регистрации
        register_btn = tk.Button(button_frame, text="Регистрация", 
                               command=self.register,
                               bg='#e74c3c', fg='white', font=('Arial', 14, 'bold'),
                               relief='raised', bd=2, padx=35, pady=12,
                               cursor='hand2')
        register_btn.pack(side=tk.RIGHT)
        
        # Подсказка
        hint_label = tk.Label(main_frame, text="💡 Вы можете изменить размер окна", 
                            font=('Arial', 10), bg='#2c0c0c', fg='#ff9999',
                            pady=10)
        hint_label.pack(fill=tk.X)
    
    def login(self):
        """Обработка входа"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Ошибка", "Заполните все поля")
            return
        
        if self.db.authenticate_user(username, password):
            self.start_messenger(username)
        else:
            messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль")
    
    def register(self):
        """Обработка регистрации"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Ошибка", "Заполните все поля")
            return
        
        if len(username) < 3:
            messagebox.showerror("Ошибка", "Имя пользователя должно содержать минимум 3 символа")
            return
        
        if len(password) < 4:
            messagebox.showerror("Ошибка", "Пароль должен содержать минимум 4 символа")
            return
        
        if self.db.register_user(username, password):
            messagebox.showinfo("Успех", "Регистрация завершена. Теперь вы можете войти.")
        else:
            messagebox.showerror("Ошибка", "Пользователь с таким именем уже существует")
    
    def start_messenger(self, username):
        """Запуск мессенджера"""
        self.root.withdraw()  # Скрываем окно входа
        
        # Создаем главное окно
        main_root = tk.Toplevel(self.root)
        messenger = MulticastMessenger(username)
        messenger.start()
        
        gui = MessengerGUI(main_root, messenger)
        
        # Обработка закрытия окна
        def on_closing():
            if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?"):
                messenger.stop()
                main_root.destroy()
                self.root.destroy()
        
        main_root.protocol("WM_DELETE_WINDOW", on_closing)
        main_root.focus_set()

def main():
    """Главная функция"""
    root = tk.Tk()
    login_app = LoginWindow(root)
    
    def on_closing():
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()