# SOCKS5, клиентская часть.

# Импортируем библиотеки.
import socket # создание сетевых соединений и работа с сокетами.
import threading # для многопоточной обработки клиентов.
import struct # для работы с бинарными данными (упаковка длины сообщений).
import logging # логирование.
from Crypto.Cipher import AES # алгоритм симметричного шифрования.
from Crypto.Util.Padding import pad, unpad # для дополнения данных до размера блока шифрования.
from Crypto.Random import get_random_bytes # для генерации криптографически безопасных случайных чисел.
import hashlib # hashlib - для хэширования данных.
import hmac # hmac - для проверки целостности и подлинности сообщений.

# Заводим класс EncryptedSocksClient.
class EncryptedSocksClient:

    # Конструктор класса. Здесь принимающий адрес сервера и порт по умолчанию 1080, стандартный порт SOCKS.
    def __init__(self, server_host, server_port=1080):

        # Сохранение параметров сервера в атрибутах объекта для последующего использования.
        self.server_host = server_host
        # Сохраняем порт прокси-сервера (по умолчанию 1080).
        self.server_port = server_port

        # Настраиваем систему логирования с уровнем INFO.
        logging.basicConfig(
            # Устанавливаем уровень детализации (информационные сообщения и выше).
            level=logging.INFO,
            # Шаблон вывода: время, уровень важности, сообщение.
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        # Создаём именованный логгер для текущего модуля.
        self.logger = logging.getLogger(__name__)

        # Задаём пароль для генерации криптографических ключей.
        password = "123456789"
        # Генерируем ключ шифрования и аутентификации с помощью PBKDF2.
        # pbkdf2_hmac - функция наследования ключа на основе пароля.
        # sha256 - используемая хеш-функция.
        # password.encode() - преобразование пароля в байтовую строку.
        # b'salt_enc', b'salt_auth' - соли для разных ключей.
        # 100000 - количество итераций для замедления brute-force атак.
        # 32 - длина генерируемого ключа в байтах (256 бит для AES-256).
        self.enc_key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt_enc', 100000, 32)
        # Генерируем такой же ключ аутентификации длиной 32 байта.
        self.auth_key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt_auth', 100000, 32)

    # Заводим функцию шифрования.
    def encrypt(self, data):
        """Шифрование данных с добавлением HMAC"""
        try:
            # Генерируем случайный вектор инициализации длиной 16 байт - случайного значения,
            # обеспечивающего уникальность шифрования даже для одинаковых данных.
            iv = get_random_bytes(16)

            # Создаём объект шифра AES в режиме CBC (Cipher Block Chaining) с указанным
            # ключом и вектором инициализации.
            cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)

            # Шифрование данных с предварительным дополнением до размера блока AES (16 байт)
            # с помощью PKCS7 padding
            encrypted = cipher.encrypt(pad(data, AES.block_size))

            # Создаём объект HMAC (hash-based message authentication code) для вычисления
            # криптографического хеша от объединения IV и зашифрованных данных.
            h = hmac.new(self.auth_key, iv + encrypted, hashlib.sha256)

            # Вычисляем дайджест HMAC длиной 32 байта (SHA-256).
            hmac_digest = h.digest()

            # Возвращаем результат в формате IV (16 байт) + зашифрованные данные + HMAC (32 байта)
            return iv + encrypted + hmac_digest

        # Перехват ошибок и логирование исключений с последующим повторным райзом ошибки.
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise

    # Заводим функцию дешифровки (decrypt).
    def decrypt(self, encrypted_data):
        """Дешифрование данных с проверкой HMAC"""
        try:

            # Проверяем минимальную длину данных (16 байт IV + 32 байта HMAC = 48 байт).
            if len(encrypted_data) < 16 + 32:  # IV (16) + HMAC (32)
                raise ValueError("Data too short for decryption")

            # Разделение входных данных на составляющие: IV, зашифрованный текст и HMAC.

            # Извлекаем вектор инициализации.
            iv = encrypted_data[:16]
            # Извлекаем зашифрованные данные.
            ciphertext = encrypted_data[16:-32]
            # Извлекаем полученный HMAC.
            received_hmac = encrypted_data[-32:]

            # Вычисляем HMAC для проверки от полученных данных и безопасно сравниваем с полученным
            # HMAC с использованием compare_digest для защиты от timing-атак.
            h = hmac.new(self.auth_key, iv + ciphertext, hashlib.sha256)
            if not hmac.compare_digest(h.digest(), received_hmac):
                raise ValueError("HMAC verification failed")

            # Создаём объект дешифратора AES-CBC с тем же ключом и IV.
            cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
            # Дешифруем и удаляем дополнение.
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            # Возврат дешифрованных данных.
            return decrypted

        # Обработка и логирование ошибок дешифрования.
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise

    # ОБРАБОТКА ЛОКАЛЬНЫХ КЛИЕНТОВ.
    # Заводим функцию handle_local_client
    def handle_local_client(self, local_client, dest_host, dest_port):
        """Обработка локального клиента"""
        try:
            # Устанавливаем таймаут 30 секунд на операции с локальным клиентом.
            local_client.settimeout(30.0)

            # Получение начального пакета от клиента (максимум 256 байт).
            data = local_client.recv(256)

            # Проверяет версию SOCKS5 (первый байт должен быть (0x05) и закрытие соединения при несоответствии.
            if not data or data[0] != 0x05:
                self.logger.warning("Invalid SOCKS version from local client")
                local_client.close()
                return

            # Отправляем клиенту ответ: версия SOCKS5 (0x05) +
            # выбранный метод аутентификации (0x00 - без аутентификации).
            local_client.send(b'\x05\x00')

            # 2. Получение SOCKS5 запроса от клиента и проверка его наличия.
            request = local_client.recv(256)
            if not request:
                local_client.close()
                return

            # Создание нового TCP-сокета для подключения к удалённому прокси-серверу
            # и установка таймаута в 30 секунд.
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.settimeout(30.0)
            # Подключение к указанному прокси-серверу.
            proxy_sock.connect((self.server_host, self.server_port))

            # Отправляем handshake прокси-серверу: версия SOCKS5 (0x05) + количество методов
            # (0x01) + метод аутентификации (0x00)
            proxy_sock.send(b'\x05\x01\x00')  # Версия + 1 метод + NO AUTH

            # Получение ответа от прокси и проверка успешности аутентификации (должен быть 0x05 и 0x00).
            response = proxy_sock.recv(2)
            if response != b'\x05\x00':
                raise Exception("Proxy authentication failed") # Выводим сообщение, если auth не прошёл.

            # Шифрование оригинального SOCKS5 запроса и отправка его прокси-серверу.
            encrypted_request = self.encrypt(request) # шифрование
            proxy_sock.send(encrypted_request) # отправка

            # Получаем зашифрованный ответ от прокси, дешифруем его и отправляем локальному клиенту.
            encrypted_response = proxy_sock.recv(4096) # получение
            response = self.decrypt(encrypted_response) # дешифровка
            local_client.send(response) # отправка локальному клиенту

            # Запуск туннелирования между клиентом и прокси.
            self.tunnel_data(local_client, proxy_sock)

        # Обработка исключений с логированием ошибок и гарантированным закрытием клиентского соединения.
        except Exception as e:
            self.logger.error(f"Error handling local client: {e}") # логирование
            try:
                local_client.close() # гарантированное закрытие
            except:
                pass

    # Объявляем метод туннелирования данных.
    def tunnel_data(self, local_client, proxy_sock):
        """Туннелирование данных между локальным клиентом и прокси"""

        # Вложенная функция для передачи данных от локального пользователя к прокси-серверу.
        def local_to_proxy():
            """Локальный клиент -> Прокси сервер"""
            try:
                # Бесконечный цикл чтения данных от клиента (блоками до 8192 байт) с выходом
                # при отсутствии данных.
                while True:
                    data = local_client.recv(8192)
                    if not data:
                        break

                    # Шифрование полученных данных, упаковка длины зашифрованного блока
                    # в 4 байта (big-endian) и отправка длины + данных прокси.
                    encrypted = self.encrypt(data)
                    length_prefix = struct.pack('>I', len(encrypted))
                    proxy_sock.send(length_prefix + encrypted)

            # Обработка таймаута и других исключений с отладочным логированием.
            except socket.timeout:
                self.logger.debug("Timeout in local_to_proxy")
            except Exception as e:
                self.logger.debug(f"local_to_proxy closed: {e}")

        # Внутренняя функция для передачи данных от прокси-сервера к локальному клиенту.
        def proxy_to_local():
            """Прокси сервер -> Локальный клиент"""
            try:

                # Бесконечный цикл чтения префикса длины (4 байта) от прокси с выходом
                # при отсутствии данных.
                while True:

                    # Читаем длину зашифрованного блока.
                    length_data = proxy_sock.recv(4)
                    if not length_data:
                        break

                    # Распаковка длины зашифрованного блока из 4-байтного представления.
                    length = struct.unpack('>I', length_data)[0]

                    # Постепенное чтение зашифрованного блока целиком, по частям,
                    # пока не будет получено указанное количество байт.
                    encrypted_data = b''
                    while len(encrypted_data) < length:
                        chunk = proxy_sock.recv(length - len(encrypted_data))
                        if not chunk:
                            break
                        encrypted_data += chunk

                    # Выход из цикла при отсутствии данных.
                    if not encrypted_data:
                        break

                    # Дешифрование полученных данных и отправка их локальному клиенту
                    # с обработкой ошибок дешифрования.
                    try:
                        decrypted = self.decrypt(encrypted_data) # дешифрование
                        local_client.send(decrypted) # отправка
                    # обработка ошибок дешифрования
                    except Exception as e:
                        self.logger.error(f"Decryption error in tunnel: {e}")
                        break

            # Обработка таймаута и других исключений + логирование.
            except socket.timeout:
                self.logger.debug("Timeout in proxy_to_local")
            except Exception as e:
                self.logger.debug(f"proxy_to_local closed: {e}")

        # Создание потоков для двух направлений передачи данных.
        t1 = threading.Thread(target=local_to_proxy) # от локального клиента к прокси
        t2 = threading.Thread(target=proxy_to_local) # от прокси к локальному клиенту

        # Установка потоков как демонов (автоматическое завершение при завершении основного потока)
        t1.daemon = True
        t2.daemon = True

        # Запуск потоков выполнения.
        t1.start()
        t2.start()

        # Логирование начала туннелирования.
        self.logger.info("Tunnel started")

        # Ждем завершения обоих потоков.
        t1.join()
        t2.join()

        # Гарантированное закрытие соединений с обработкой возможных исключений.
        try:
            local_client.close()
        except:
            pass
        try:
            proxy_sock.close()
        except:
            pass

        # Логирование завершения туннелирования.
        self.logger.info("Tunnel closed")

    # Объявление метода запуска локального SOCKS5 прокси.
    # dest_host - целевой хост к которому будет туннелироваться трафик.
    # dest_port - порт целевого хоста.
    # local_port = 1081 - локальный порт для SOCKS5 прокси (значение по умолчанию 1081).
    def start_local_proxy(self, dest_host, dest_port, local_port=1081):
        """Запуск локального SOCKS5 прокси"""

        # Создание TCP-сокета для сервера, socket.AF_INET - указание использовать IPv4.
        # socket.SOCK_STREAM - указание использовать TCP протокол.
        local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Установка опции SO_REUSEADDR для немедленного повторного использования порта после перезапуска.
        local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Привязка сокета к локалхосту и указанному порту.
        local_server.bind(('127.0.0.1', local_port))
        # Начало прослушивания порта с очередью до 5 соединений.
        local_server.listen(5)
        # Установка таймаута на операцию accept для возможности graceful shutdown.
        local_server.settimeout(1.0)

        # Логирование информации о запущенном прокси.
        self.logger.info(f"Local SOCKS5 proxy started on 127.0.0.1:{local_port}")
        self.logger.info(f"Traffic tunneled through {self.server_host}:{self.server_port}")

        # Установка флага работы сервера.
        self.running = True

        # try/except для принятия соединений.
        try:
            while self.running:
                try:
                    # Принятие входящего соединения и получение информации о клиенте.
                    local_client, addr = local_server.accept()
                    # Логирование информации о подключившемся клиенте.
                    self.logger.info(f"Local connection from: {addr}")

                    # Создание и запуск отдельного потока для обработки клиента с установкой
                    # демонического режима.
                    client_thread = threading.Thread(
                        target=self.handle_local_client,
                        args=(local_client, dest_host, dest_port),
                        daemon=True
                    )
                    client_thread.start()

                # Пропуск итерации при таймауте accept...
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")

        # Обработка прерывания клавиатуры (Ctrl + C) с информационным сообщением.
        except KeyboardInterrupt:
            self.logger.info("Stopping local proxy...")
        # Логирование других ошибок сервера.
        except Exception as e:
            self.logger.error(f"Local proxy error: {e}")

        # Гарантированное снятие флага и закрытие серверного сокета.
        finally:
            self.running = False
            local_server.close()
            self.logger.info("Local proxy stopped")

if __name__ == "__main__":
    # Определение параметров.
    PROXY_SERVER = "10.1.1.56"  # IP вашего VPS
    DESTINATION_HOST = "youtube.com"  # Целевой сайт для туннелирования
    DESTINATION_PORT = 443 # порт целевого хоста (443 - HTTPS)
    LOCAL_PORT = 1081 # локальный порт для SOCKS5 прокси

    # Создание экземпляра клиента зашифрованного SOCKS5 прокси.
    client = EncryptedSocksClient(PROXY_SERVER)
    # Запуск локального прокси с указанными параметрами.
    client.start_local_proxy(DESTINATION_HOST, DESTINATION_PORT, LOCAL_PORT)