# SOCKS5_Client_Encrypt.py, #4.
# Модуль шифрования и дешифрования данных
# Отвечает за криптографические операции: шифрование AES-CBC и проверку целостности HMAC

# Импортируем библиотеки для криптографических операций
from Crypto.Cipher import AES  # алгоритм симметричного шифрования AES
from Crypto.Util.Padding import pad, unpad  # для дополнения данных до размера блока
from Crypto.Random import get_random_bytes  # для генерации криптографически безопасных случайных чисел
import hashlib  # для хеширования данных (SHA-256)
import hmac  # для проверки целостности и подлинности сообщений

def encrypt(client_self, data):
    """Шифрование данных с добавлением HMAC"""
    try:
        # Генерируем случайный вектор инициализации длиной 16 байт
        # Обеспечивает уникальность шифрования даже для одинаковых данных
        # 128-bit cryptographically secure random IV
        iv = get_random_bytes(16)

        # Создаём объект шифра AES в режиме CBC (Cipher Block Chaining)
        # с указанным ключом шифрования и вектором инициализации
        cipher = AES.new(client_self.enc_key, AES.MODE_CBC, iv)

        # Шифрование данных с предварительным дополнением до размера блока AES (16 байт)
        # с помощью PKCS7 padding
        encrypted = cipher.encrypt(pad(data, AES.block_size))

        # Создаём объект HMAC (Hash-based Message Authentication Code)
        # для вычисления криптографического хеша от объединения IV и зашифрованных данных.
        # HMAC защищает от модифицированных данных: без правильного ключа аутентификации
        # невозможно подделать сообщение, даже если злоумышленник знает незашифрованные данные.
        h = hmac.new(client_self.auth_key, iv + encrypted, hashlib.sha256)

        # Вычисляем дайджест HMAC длиной 32 байта (SHA-256)
        hmac_digest = h.digest()

        # Возвращаем результат в формате: IV (16 байт) + зашифрованные данные + HMAC (32 байта)
        # Такая структура позволяет при дешифровании извлечь все компоненты
        return iv + encrypted + hmac_digest

    # Перехват ошибок и логирование исключений с последующим повторным возбуждением ошибки
    except Exception as e:
        client_self.logger.error(f"Encryption error: {e}")
        raise

def decrypt(client_self, encrypted_data):
    """Дешифрование данных с проверкой HMAC"""
    try:
        # Проверяем минимальную длину данных (16 байт IV + 32 байта HMAC = 48 байт)
        # Если данных меньше - невозможно корректно извлечь все компоненты
        if len(encrypted_data) < 16 + 32:  # IV (16) + HMAC (32)
            raise ValueError("Data too short for decryption")

        # Разделение входных данных на составляющие: IV, зашифрованный текст и HMAC

        # Извлекаем вектор инициализации - первые 16 байт
        iv = encrypted_data[:16]
        # Извлекаем зашифрованные данные - от 16 байта до 32 байта с конца
        ciphertext = encrypted_data[16:-32]
        # Извлекаем полученный HMAC - последние 32 байта
        received_hmac = encrypted_data[-32:]

        # Вычисляем HMAC для проверки целостности данных
        # Используем тот же ключ аутентификации и те же данные (IV + ciphertext)
        h = hmac.new(client_self.auth_key, iv + ciphertext, hashlib.sha256)

        # compare_digest защищает от timing-атак, которые могут раскрыть информацию
        # о правильности HMAC путём измерения времени сравнения.
        if not hmac.compare_digest(h.digest(), received_hmac):
            raise ValueError("HMAC verification failed")

        # Создаём объект дешифратора AES-CBC с тем же ключом и IV
        cipher = AES.new(client_self.enc_key, AES.MODE_CBC, iv)

        # Дешифруем данные и удаляем дополнение PKCS7
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Возвращаем дешифрованные данные
        return decrypted

    # Обработка и логирование ошибок дешифрования
    except Exception as e:
        client_self.logger.error(f"Decryption error: {e}")
        raise