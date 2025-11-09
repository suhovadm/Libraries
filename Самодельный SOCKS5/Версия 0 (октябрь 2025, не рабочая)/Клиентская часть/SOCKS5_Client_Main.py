# SOCKS5_Client_Main.py, #1.
# Основной файл клиента зашифрованного SOCKS5 прокси
# Координирует работу всех модулей и предоставляет главный интерфейс

# Импортируем библиотеки.
import logging  # логирование.
import hashlib  # hashlib - для хэширования данных.

# Импортируем модули с функциями, разделёнными по функциональности
from SOCKS5_Client_Encrypt import encrypt, decrypt
from SOCKS5_Client_Handler import handle_local_client
from SOCKS5_Client_Tunnel import tunnel_data
from SOCKS5_Client_Proxy import start_local_proxy

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

    # Делегируем метод шифрования соответствующему модулю
    # client_self передаётся для доступа к ключам и логгеру
    def encrypt(self, data):
        """Шифрование данных с добавлением HMAC"""
        return encrypt(self, data)

    # Делегируем метод дешифрования соответствующему модулю
    def decrypt(self, encrypted_data):
        """Дешифрование данных с проверкой HMAC"""
        return decrypt(self, encrypted_data)

    # Делегируем обработку клиентов соответствующему модулю
    def handle_local_client(self, local_client):
        """Обработка локального клиента"""
        return handle_local_client(self, local_client)

    # Делегируем туннелирование данных соответствующему модулю
    def tunnel_data(self, local_client, proxy_sock):
        """Туннелирование данных между локальным клиентом и прокси"""
        return tunnel_data(self, local_client, proxy_sock)

    # Делегируем запуск прокси соответствующему модулю
    def start_local_proxy(self, local_port=1081):
        """Запуск локального SOCKS5 прокси"""
        return start_local_proxy(self, local_port)

# Точка входа программы
if __name__ == "__main__":
    # Определение параметров.
    PROXY_SERVER = "10.1.1.56"  # IP нашего VPS
    LOCAL_PORT = 1081  # локальный порт для SOCKS5 прокси

    # Создание экземпляра клиента зашифрованного SOCKS5 прокси.
    client = EncryptedSocksClient(PROXY_SERVER)
    # Запуск локального прокси с указанными параметрами.
    client.start_local_proxy(LOCAL_PORT)