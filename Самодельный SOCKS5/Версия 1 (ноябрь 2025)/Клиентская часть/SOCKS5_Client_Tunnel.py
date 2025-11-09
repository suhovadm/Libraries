# SOCKS5_Client_Tunnel.py, #5.
# Модуль туннелирования данных между клиентом и прокси
# Создает двунаправленный зашифрованный канал для передачи данных

# Импортируем библиотеки для многопоточности и работы с бинарными данными
import threading  # для создания параллельных потоков передачи данных
import struct  # для упаковки/распаковки длины сообщений
import socket  # для работы с сокетами и обработки таймаутов

def local_to_proxy(client_self, local_client, proxy_sock):
    """Передача данных от локального клиента к прокси-серверу"""
    try:
        # Бесконечный цикл чтения данных от клиента (блоками до 8192 байт)
        # с выходом при отсутствии данных (разрыв соединения)
        while True:
            # Чтение данных от локального клиента
            # 8192 байта - оптимальный размер для баланса между latency и throughput
            data = local_client.recv(8192)
            if not data:
                break  # Выход из цикла при разрыве соединения

            # Шифрование полученных данных, упаковка длины зашифрованного блока
            # в 4 байта (big-endian) и отправка длины + данных прокси.
            # Протокол туннеля: [4 байта длинна][N байт зашифрованные данные]
            # Длина указывает размер зашифрованного блока (big-endian).
            encrypted = client_self.encrypt(data)  # Шифруем данные
            length_prefix = struct.pack('>I', len(encrypted))  # Упаковываем длину в 4 байта
            proxy_sock.send(length_prefix + encrypted)  # Отправляем длину + зашифрованные данные

    # Обработка таймаута - нормальная ситуация при отсутствии данных
    except socket.timeout:
        client_self.logger.debug("Timeout in local_to_proxy")
    # Обработка других исключений с отладочным логированием
    except Exception as e:
        client_self.logger.debug(f"local_to_proxy closed: {e}")

def proxy_to_local(client_self, local_client, proxy_sock):
    """Передача данных от прокси-сервера к локальному клиенту"""
    try:
        # Бесконечный цикл чтения префикса длины (4 байта) от прокси
        # с выходом при отсутствии данных (разрыв соединения)
        while True:
            # Читаем длину зашифрованного блока - первые 4 байта (read length prefix)
            length_data = proxy_sock.recv(4)
            if not length_data:
                break  # Выход при разрыве соединения

            # Распаковка длины зашифрованного блока из 4-байтного представления
            # '>I' означает big-endian unsigned int (4 байта)
            length = struct.unpack('>I', length_data)[0] # unpack to int

            # Постепенное чтение зашифрованного блока целиком, по частям,
            # пока не будет получено указанное количество байт
            encrypted_data = b''  # Буфер для накопления данных
            while len(encrypted_data) < length:
                # Читаем оставшуюся часть данных
                chunk = proxy_sock.recv(length - len(encrypted_data))
                if not chunk:
                    break  # Выход при разрыве соединения
                encrypted_data += chunk  # Добавляем чанк к буферу

            # Выход из цикла при отсутствии данных
            if not encrypted_data:
                break

            # Дешифрование полученных данных и отправка их локальному клиенту
            # с обработкой ошибок дешифрования
            try:
                decrypted = client_self.decrypt(encrypted_data)  # дешифрование
                local_client.send(decrypted)  # отправка дешифрованных данных клиенту
            # Обработка ошибок дешифрования - критическая ошибка, разрываем соединение
            except Exception as e:
                client_self.logger.error(f"Decryption error in tunnel: {e}")
                break

    # Обработка таймаута - нормальная ситуация
    except socket.timeout:
        client_self.logger.debug("Timeout in proxy_to_local")
    # Обработка других исключений с отладочным логированием
    except Exception as e:
        client_self.logger.debug(f"proxy_to_local closed: {e}")

def tunnel_data(client_self, local_client, proxy_sock):
    """Туннелирование данных между локальным клиентом и прокси"""

    # Создание потоков для двух направлений передачи данных
    # Каждый поток работает независимо, обеспечивая полнодуплексную связь
    t1 = threading.Thread(target=local_to_proxy,
                          args=(client_self, local_client, proxy_sock))  # от локального клиента к прокси
    t2 = threading.Thread(target=proxy_to_local,
                          args=(client_self, local_client, proxy_sock))  # от прокси к локальному клиенту

    # Установка потоков как демонов (автоматическое завершение при завершении основного потока)
    # Гарантирует, что потоки не останутся висеть при завершении программы
    t1.daemon = True
    t2.daemon = True

    # Запуск потоков выполнения
    # Теперь данные могут передаваться в обоих направлениях одновременно
    t1.start()
    t2.start()

    # Логирование начала туннелирования
    client_self.logger.info("Tunnel started")

    # Ожидание завершения обоих потоков
    # join() блокирует выполнение до завершения потоков
    t1.join()
    t2.join()

    # Гарантированное закрытие соединений с обработкой возможных исключений
    # Важно для освобождения ресурсов даже при ошибках
    try:
        local_client.close()  # Закрываем соединение с локальным клиентом
    except:
        pass  # Игнорируем ошибки при закрытии
    try:
        proxy_sock.close()  # Закрываем соединение с прокси-сервером
    except:
        pass  # Игнорируем ошибки при закрытии

    # Логирование завершения туннелирования
    client_self.logger.info("Tunnel closed")