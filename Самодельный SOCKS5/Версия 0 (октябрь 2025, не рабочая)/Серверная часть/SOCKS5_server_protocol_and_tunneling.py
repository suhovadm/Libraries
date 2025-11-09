# 4. Основной модуль обработки SOCKS5 протокола и туннелирования данных.

import socket # для сетевых соединений.
import struct # для работы с бинарными данными (упаковка и распаковка).
import threading # для многопоточности.
import ipaddress # для работы с IP адресами и подсетями.
from typing import Optional, Tuple # аннотации типов для лучшей читаемости.
from SOCKS5_server_config import ServerConfig # конфигурация сервера.

# Заводим класс AddressValidator - валидатор адресов.
class AddressValidator:

    # Конструктор класса, инициализирует объект.
    def __init__(self):

        # Запрещенные подсети из конфигурации.
        # Преобразуем список запрещённых сетей в объекты IPv4Network.
        # В данном случае, мы проверяем, разрешено ли подключение к целевому адресу.
        self.forbidden_nets = [ipaddress.IPv4Network(net) for net in ServerConfig.FORBIDDEN_NETWORKS]

    # Метод validate_address. Валидация целевых адресов.
    def validate_address(self, addr: str, port: int) -> bool:
        try:
            # Проверка порта. 1 <= port <= 65535 - порт должен быть в допустимом диапазоне.
            if not (1 <= port <= 65535):
                return False # возвращает False, если порт вне диапазона.

            # Проверка IP адреса.
            # Пытается преобразовать строку в объект IPv4Address
            # Если преобразование успешно - это IP адрес.
            try:
                ip = ipaddress.IPv4Address(addr)

                # Проверка на запрещенные подсети.
                # Проверяем, не находится ли IP в запрещённых подсетях.
                for net in self.forbidden_nets:
                    if ip in net:
                        return False # возвращает False, если IP находится в запрещённой подсети.

            # Ловим исключение, если addr не является валидным IPv4 адресом.
            # Это означает, что addr - доменное имя.
            except ipaddress.AddressValueError:
                pass # для доменных имен просто пропускаем проверку подсетей.

            # Если все проверки пройдены - возвращаем True.
            return True

        # Ловим любые другие исключения.
        except Exception:
            return False # возвращает False при любой другой ошибке.

# Заводим класс ProtocolHandler.
class ProtocolHandler:
    """Обработчик SOCKS5 протокола"""

    # Конструктор, принимает объекты для шифрования и логирования.
    def __init__(self, crypto, logger):

        # Инициализация полей класса.
        self.crypto = crypto # объект для криптографических операций.
        self.logger = logger # объект для логирования.
        self.address_validator = AddressValidator() # создаёт валидатор адресов.

    # Метод аутентификации клиента по токену.
    def authenticate_client(self, client_sock: socket.socket) -> bool:

        # Блок обработки исключений аутентификации.
        try:
            client_sock.settimeout(5.0) # устанавливаем таймаут 5 секунд на операцию recv (получение данных).
            auth_token = client_sock.recv(32) # получаем 32 байта - токен аутентификации

        # Проверяем, что получено ровно 32 байта.
            if len(auth_token) != 32:

                # Логирует предупреждение о неверной длине токена.
                self.logger.warning("Invalid auth token length")
                return False # False при неверной длине.

        # Проверяем токен через криптографический модуль.
            if not self.crypto.verify_token(auth_token):

                # Логирует неудачную аутентификацию.
                self.logger.warning("Authentication failed")
                return False # False при неверном токене.

            return True # True при успешной аутентификации.

        # Обработка исключений таймаута и других ошибок.
        except socket.timeout:
            self.logger.warning("Authentication timeout")
            return False
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False

    # Метод handle_handshake.
    # Обрабатывает SOCKS5 handshake последовательность:
    # 1. Аутентификация клиента по токену.
    # 2. Negotiation методы (только no auth).
    # 3. Парсинг connect запросов.
    # 4. Валидация целевого адреса.
    # 5. Установка соединения с целевым сервером.
    # 6. Отправка зашифрованного ответа клиенту.
    # 7. Возвращает сокет подключения к целевому серверу или None при ошибке.
    def handle_handshake(self, client_sock: socket.socket) -> Optional[socket.socket]:

        # Блок обработки исключений handshake.
        try:
            client_sock.settimeout(ServerConfig.HANDSHAKE_TIMEOUT) # устанавливаем таймаут handshake из конфига.

            # Аутентификация клиента
            if not self.authenticate_client(client_sock):
                return None # None, если аутентификация не прошла.

            # Получает данные SOCKS5 handshake (максимум 256 байт).
            data = client_sock.recv(256)

            # Проверяет что данные получены и первый байт = 0x05 (версия SOCKS5)
            if not data or data[0] != 0x05:

                # Логируем неверную версию SOCKS.
                self.logger.warning("Invalid SOCKS version")
                return None # Возвращаем None при неверной версии.

            # Отправляем клиенту: версия SOCKS5 (0x05), метод аутентификации - без аутентификации (0x00).
            client_sock.send(b'\x05\x00')

            # Получает зашифрованный SOCKS5 запрос.
            encrypted_request = client_sock.recv(4096)
            # Дешифрует запрос.
            request = self.crypto.decrypt(encrypted_request)

            # Проверяет что запрос дешифрован и версия действительно SOCKS5.
            if not request or request[0] != 0x05:
                return None

            # Парсим запрос.
            # Проверяет что команда = 1 (CONNECT).
            # SOCKS5 команды: 1 = CONNECT, 2 = BIND, 3 = UDP ASSOCIATE.
            if request[1] != 1:  # Только CONNECT

                # Отправляет ошибку: команда не поддерживается (0x07).
                client_sock.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return None

            # Извлекаем адрес и порт.
            # Получаем тип адреса из 4-го байта запроса.
            addr_type = request[3]

            # Если тип адреса = 1 (IPv4 адрес)
            if addr_type == 1:
                # Преобразует 4 байта IP адреса в строку
                dest_addr = socket.inet_ntoa(request[4:8])
                # Распаковывает 2 байта порта в big-endian формате
                dest_port = struct.unpack('>H', request[8:10])[0]

            # Если тип адреса = 3 (доменное имя).
            elif addr_type == 3:

                # Получаем длину доменного имени из 5-го байта.
                domain_length = request[4]
                # Извлекаем доменное имя и декодируем его в строку.
                dest_addr = request[5:5 + domain_length].decode()
                # Распаковываем порт после доменного имени.
                dest_port = struct.unpack('>H', request[5 + domain_length:7 + domain_length])[0]
            else:
                return None

            # Валидация адреса.
            if not self.address_validator.validate_address(dest_addr, dest_port):

                # Логирует неудачную валидацию адреса.
                self.logger.warning(f"Address validation failed: {dest_addr}:{dest_port}")
                # Отправляет ошибку: соединение запрещено (0x02).
                client_sock.send(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')
                return None

            # Логирует попытку подключения.
            self.logger.info(f"Connecting to: {dest_addr}:{dest_port}")

            # Подключаемся к целевому серверу.
            # Создаёт новый TCP сокет для подключения к целевому серверу.
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Устанавливает таймаут на подключение.
            remote_sock.settimeout(ServerConfig.HANDSHAKE_TIMEOUT)
            # Подключаемся к целевому серверу.
            remote_sock.connect((dest_addr, dest_port))

            # Отправляем успешный ответ.
            # Получаем локальный адрес и порт сокета.
            bound_addr = remote_sock.getsockname()
            # Формируем SOCKS5 ответ:
            # 0x05: версия SOCKS5,
            # 0x00: успешное выполнение,
            # 0x00: зарезервированный байт,
            # 0x01: тип адреса (IPv4),
            # IP и порт сервера.
            reply = b'\x05\x00\x00\x01' + socket.inet_aton(bound_addr[0]) + struct.pack('>H', bound_addr[1])
            # Шифрует и отправляет ответ клиенту.
            client_sock.send(self.crypto.encrypt(reply))

            # Возвращает сокет подключения к целевому серверу.
            return remote_sock

        # Перехват возможных ошибок и логирование оных.
        except Exception as e:
            self.logger.error(f"Handshake error: {e}")
            return None

# Заводим класс TunnelManager.
# Менеджер туннелирования данных.
class TunnelManager:

    # Конструктор менеджера туннелей.
    def __init__(self, crypto, logger):

        # Инициализируем поля.
        self.crypto = crypto # объект для шифрования.
        self.logger = logger # объект для логирования.

    # Запускаем туннель между клиентом и удалённым сервером.
    def start_tunnel(self, client_sock: socket.socket, remote_sock: socket.socket, addr: Tuple[str, int]):

        # Флаг работы туннеля в списке для обхода ограничения nonlocal.
        running = [True]

        # Функция client_to_remote.
        # Функция передачи данных от клиента к удалённому серверу.
        def client_to_remote():
            """Клиент -> Сервер -> Удаленный хост"""

            # Цикл пока туннель активен.
            while running[0]:
                try:
                    # Получаем 4 байта длины зашифрованных данных.
                    length_data = client_sock.recv(4)
                    # Проверяет что данные получены и что они не пустые.
                    if not length_data:
                        break # Выходим из цикла, если соединение разорвано.

                    # Распаковываем длину как 4-байтное беззнаковое integer big-endian
                    length = struct.unpack('>I', length_data)[0]

                    # Проверка размера данных.
                    # Проверяет что длина не превышает максимальный разрешённый размер.
                    if length > ServerConfig.MAX_DATA_SIZE:
                        # Логируем ошибку слишком больших данных.
                        self.logger.error(f"Data too large from {addr}: {length}")
                        break # Прерываем туннель при слишком больших данных.

                    # Читаем зашифрованные данные.
                    # Инициализируем пустой буфер для зашифрованных данных.
                    encrypted_data = b''

                    # Цикл чтения работает пока не получены все данные и туннель активен.
                    while len(encrypted_data) < length and running[0]:

                        # Читает данные (максимум 4096 байт или оставшиеся данные).
                        chunk = client_sock.recv(min(4096, length - len(encrypted_data)))

                        # Проверяем, что данные не пустые.
                        if not chunk:
                            break # Выходим из цикла если соединение разорвано.

                        # Добавляем данные к буферу.
                        encrypted_data += chunk

                    # Проверяем что данные получены полностью.
                    if not encrypted_data or len(encrypted_data) != length:
                        break # Выходим если данные не полные.

                    # Дешифруем полученные данные и отправляем их на удаленный хост.
                    decrypted_data = self.crypto.decrypt(encrypted_data)
                    remote_sock.send(decrypted_data)
                except:
                    break

            # Устанавливаем флаг остановки туннеля.
            running[0] = False

# Функция remote_to_client():
# Функция передачи данных от удалённого сервера к клиенту.
        def remote_to_client():
            """Удаленный хост -> Сервер -> Клиент"""

            # Цикл работает пока туннель активен.
            while running[0]:
                try:

                    # Получает данные от удалённого сервера (максимум 8192 байта).
                    data = remote_sock.recv(8192)

                    # Проверяет что данные получены.
                    if not data:
                        break # Выход из цикла если соединение разорвано.

                    # Шифруем полученные данные.
                    encrypted_data = self.crypto.encrypt(data)
                    # Отправляет длину (4 байта) + зашифрованные данные клиенту.
                    client_sock.send(struct.pack('>I', len(encrypted_data)) + encrypted_data)
                except:
                    break

            # Устанавливаем флаг остановки туннеля.
            running[0] = False

        # Устанавливаем таймауты на сокеты.
        client_sock.settimeout(ServerConfig.TUNNEL_TIMEOUT)
        remote_sock.settimeout(ServerConfig.TUNNEL_TIMEOUT)

        # Запускаем потоки. Создание потоков для двунаправленной передачи.
        t1 = threading.Thread(target=client_to_remote, daemon=True) # t1 - для client_to_remote
        t2 = threading.Thread(target=remote_to_client, daemon=True) # t2 - для remote_to_client
        t1.start() # запустить
        t2.start() # запустить
        # daemon=True гарантирует, что потоки завершатся при завершении основной программы, даже если они активны.

        # Логирует запуск туннеля.
        self.logger.info(f"Tunnel started for {addr}")

        # Ждем завершения потоков.
        t1.join()
        t2.join()

        # Закрытие сокета удалённого сервера с обработкой исключений.
        try:
            remote_sock.close()
        except:
            pass

        # Логируем закрытие туннеля.
        self.logger.info(f"Tunnel closed for {addr}")