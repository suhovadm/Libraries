# SOCKS5_Client_Handler.py, #3.
# Модуль обработки локальных клиентов
# Проще говоря, это "переводчик" между обычными приложениями
# (которые говорят на языке SOCKS5) и нашим зашифрованным прокси (который понимает только зашифрованные сообщения).

# Импортируем библиотеку для сетевых соединений
import socket  # создание сетевых соединений и работа с сокетами

def handle_local_client(client_self, local_client):
    """Обработка локального клиента"""
    try:
        # Устанавливаем таймаут 30 секунд на операции с локальным клиентом
        # Защита от зависания при неактивных соединениях
        local_client.settimeout(30.0)

        # Получение начального пакета от клиента (максимум 256 байт)
        # В SOCKS5 это запрос методов аутентификации
        data = local_client.recv(256)

        # Проверяем версию SOCKS5 (первый байт должен быть 0x05)
        # и закрываем соединение при несоответствии
        if not data or data[0] != 0x05:
            client_self.logger.warning("Invalid SOCKS version from local client")
            local_client.close()
            return

        # Отправляем клиенту ответ: версия SOCKS5 (0x05) +
        # выбранный метод аутентификации (0x00 - без аутентификации)
        local_client.send(b'\x05\x00')

        # Получение SOCKS5 запроса от клиента и проверка его наличия
        # Запрос содержит информацию о целевом хосте и порте
        request = local_client.recv(256)
        if not request:
            local_client.close()
            return

        # Создание нового TCP-сокета для подключения к удалённому прокси-серверу
        # и установка таймаута в 30 секунд
        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_sock.settimeout(30.0)

        # Подключение к указанному прокси-серверу
        # client_self.server_host и client_self.server_port из основного класса
        proxy_sock.connect((client_self.server_host, client_self.server_port))

        # Отправляем handshake прокси-серверу: версия SOCKS5 (0x05) + количество методов
        # (0x01) + метод аутентификации (0x00 - без аутентификации)
        proxy_sock.send(b'\x05\x01\x00')  # Версия + 1 метод + NO AUTH

        # Получение ответа от прокси и проверка успешности аутентификации
        # Должен быть 0x05 0x00 (успешная аутентификация)
        response = proxy_sock.recv(2)
        if response != b'\x05\x00':
            raise Exception("Proxy authentication failed")  # Выводим сообщение, если auth не прошёл

        # Шифрование оригинального SOCKS5 запроса и отправка его прокси-серверу
        # Запрос содержит информацию о том, куда клиент хочет подключиться
        encrypted_request = client_self.encrypt(request)  # шифрование
        proxy_sock.send(encrypted_request)  # отправка

        # Получаем зашифрованный ответ от прокси, дешифруем его и отправляем локальному клиенту
        # Ответ содержит результат подключения к целевому хосту
        encrypted_response = proxy_sock.recv(4096)  # получение зашифрованного ответа
        response = client_self.decrypt(encrypted_response)  # дешифровка
        local_client.send(response)  # отправка дешифрованного ответа локальному клиенту

        # Запуск туннелирования между клиентом и прокси
        # Теперь данные могут передаваться в обе стороны через зашифрованный канал
        client_self.tunnel_data(local_client, proxy_sock)

    # Обработка исключений с логированием ошибок и гарантированным закрытием клиентского соединения
    except Exception as e:
        client_self.logger.error(f"Error handling local client: {e}")  # логирование ошибки
        try:
            local_client.close()  # гарантированное закрытие соединения с клиентом
        except:
            pass  # Игнорируем ошибки при закрытии (соединение уже могло быть закрыто)