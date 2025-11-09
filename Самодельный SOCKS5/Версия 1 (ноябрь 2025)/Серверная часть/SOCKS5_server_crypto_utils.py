# 3. Криптографический модуль SOCKS5 сервера.

# * PBKDF2 увеличивает сложность перебора паролей для brute-force атак.
# * CBC требует уникального IV для каждого шифрования, чтобы одинаковые plaintext давали разные ciphertext.

import hashlib # для хэширования и работы с криптографическими хеш-функциями.
import hmac # для создания и проверки HMAC (Hash-based Message Authenticated Code).
from Crypto.Cipher import AES # для симметричного шифрования.
from Crypto.Util.Padding import pad, unpad # для дополнения данных до нужного размера блока.
from Crypto.Random import get_random_bytes # для генерации криптографически безопасных случайных чисел.
from SOCKS5_server_config import ServerConfig # пользовательский конфиг файл с настройками безопасности.

# Заводим класс CryptoUtils.
class CryptoUtils:

    # Инициализация класса (метод init).
    def __init__(self):

        # При создании экземпляра класса генерируется три криптографических ключа:

        # enc_key - ключ для шифрования данных:
        # в нём используется алгоритм PBKDF2-HMAC-SHA256
        # на основе пароля из ServerConfig.PASSWORD
        # применяя ServerConfig.ENCRYPTION_SALT
        # Количество итераций задаётся ServerConfig.PBKDF2_ITERATIONS
        # Длина ключа - 32 байта (256 бит)
        self.enc_key = hashlib.pbkdf2_hmac(
            'sha256',
            ServerConfig.PASSWORD.encode(),
            ServerConfig.ENCRYPTION_SALT,
            ServerConfig.PBKDF2_ITERATIONS,
            32
        )

        # auth_key - ключ для аутентификации сообщений:
        # здесь используется тот же алгоритм PBKDF2-HMAC-SHA256
        # тот же пароль, но другой конфиг - ServerConfig.AUTHENTICATION_SALT
        # Разные конфиги гарантируют, что ключи шифрования и аутентификации будут различными
        self.auth_key = hashlib.pbkdf2_hmac(
            'sha256',
            ServerConfig.PASSWORD.encode(),
            ServerConfig.AUTHENTICATION_SALT,
            ServerConfig.PBKDF2_ITERATIONS,
            32
        )

        # Удаляем генерацию токена аутентификации
        # self.auth_token = hashlib.sha256(ServerConfig.AUTH_TOKEN_SECRET.encode()).digest()

    # Метод encrypt - шифрование данных.
    # Процесс шифрования данных состоит из нескольких этапов.
    def encrypt(self, data: bytes) -> bytes:
        """Шифрование данных с добавлением HMAC"""

        # Создаётся 16-байтный случайный вектор инициализации.
        # Генерация случайного вектора инициализации (16 байт).
        # IV обеспечивает уникальность шифрования даже для одинаковых данных.
        iv = get_random_bytes(16)

        # IV необходим для режима CBC (Cipher Block Chaining).
        # Каждый IV уникален для каждого шифрования.
        # Создаётся AES cipher в режиме CBC с ключом enc_key и IV.
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv) # создание шифра AES-256 в режиме CBC.

        # Данные дополняются до размера блока AES (16 байт) с помощью pad()
        # Производится шифрование данных.
        # AES.block_size равен 16 байтам (128 битам).
        encrypted = cipher.encrypt(pad(data, AES.block_size))

        # Создание HMAC для аутентификации (целостность + подлинность).
        # Генерируются HMAC-SHA256 для аутентификации сообщения.
        # HMAC-SHA256 создаёт дайджест длиной 32 байта.
        # Используется auth_key и конкатенация IV + зашифрованные данные.
        h = hmac.new(self.auth_key, iv + encrypted, hashlib.sha256)
        # HMAC обеспечивает целостность и подлинность данных.
        hmac_digest = h.digest()

        # Формат результата:
        # Возвращается объединённая строка: IV (16 байт) + зашифрованные данные + HMAC (32 байта).
        return iv + encrypted + hmac_digest

    # Метод decrypt - дешифрование данных.
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Дешифрование данных с проверкой HMAC"""
        # Убеждаемся, что данные содержат как минимум IV (16 байт) и HMAC (32 байта).
        if len(encrypted_data) < 16 + 32:  # IV (16) + HMAC (32).
            raise ValueError("Data too short for decryption")

        # Разделение компонентов.
        iv = encrypted_data[:16] # IV: первые 16 байт.
        ciphertext = encrypted_data[16:-32] # ciphertext: данные между IV и HMAC (с 16-го байта до 32-го с конца)
        received_hmac = encrypted_data[-32:] # received_hmac: последние 32 байта.

        # Проверяем HMAC (верификация HMAC).

        # Вычисляем HMAC для полученных iv + ciphertext
        h = hmac.new(self.auth_key, iv + ciphertext, hashlib.sha256)

        # Сравниваем с полученными HMAC с использованием hmac.compare_digest()
        # Эта функция защищена от timing-атак.
        if not hmac.compare_digest(h.digest(), received_hmac):
            raise ValueError("HMAC verification failed")

        # Дешифрование.
        # Создаём AES cipher с теми же параметрами.
        # Данные дешифруются.
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)

        # Удаляется дополнение с помощью unpad()
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted

    # Удаляем метод verify_token() - проверка токена больше не нужна
    # def verify_token(self, token: bytes) -> bool:
    #     """Проверка токена аутентификации"""
    #     return hmac.compare_digest(token, self.auth_token)