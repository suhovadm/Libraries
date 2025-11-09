# SOCKS5_Client_Proxy.py, #2.
# Модуль запуска локального SOCKS5 прокси
# Простыми словами, это - "маскировочный слой" между нашим приложениями и зашифрованным туннелем.

# Импортируем библиотеки для создания сервера и многопоточности
import socket  # для создания серверного сокета и принятия подключений
import threading  # для обработки каждого клиента в отдельном потоке

def start_local_proxy(client_self, local_port=1081):
    """Запуск локального SOCKS5 прокси"""

    # Создание TCP-сокета для сервера
    # socket.AF_INET - указание использовать IPv4 адресацию
    # socket.SOCK_STREAM - указание использовать TCP протокол (надёжный, с установкой соединения)
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Установка опции SO_REUSEADDR для немедленного повторного использования порта после перезапуска
    # Позволяет избежать ошибки "Address already in use" при быстром перезапуске сервера
    local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Привязка сокета к локалхосту и указанному порту
    # 127.0.0.1 - только локальные подключения (безопаснее)
    # local_port - порт, на котором будет работать SOCKS5 прокси
    local_server.bind(('127.0.0.1', local_port))

    # Начало прослушивания порта с очередью до 5 соединений
    # Операционная система будет хранить до 5 подключений в очереди ожидания
    local_server.listen(5)

    # Установка таймаута на операцию accept для возможности graceful shutdown
    # Без этого сервер будет бесконечно блокироваться на accept()
    local_server.settimeout(1.0)

    # Логирование информации о запущенном прокси
    client_self.logger.info(f"Local SOCKS5 proxy started on 127.0.0.1:{local_port}")
    client_self.logger.info(f"Traffic tunneled through {client_self.server_host}:{client_self.server_port}")

    # Установка флага работы сервера
    # Контролирует выполнение основного цикла сервера
    client_self.running = True

    # Основной цикл принятия соединений с обработкой исключений
    try:
        # Бесконечный цикл, выполняющийся пока сервер работает (self.running = True)
        while client_self.running:
            try:
                # Принятие входящего соединения и получение информации о клиенте
                # accept() - блокирующая операция, но из-за таймаута 1.0 секунда блокировки максимум
                local_client, addr = local_server.accept()

                # Логирование информации о подключившемся клиенте
                # addr - кортеж (IP-адрес, порт) подключившегося клиента
                client_self.logger.info(f"Local connection from: {addr}")

                # Создание и запуск отдельного потока для обработки клиента с установкой
                # демонического режима
                # Каждый клиент обрабатывается в отдельном потоке для параллельной работы
                client_thread = threading.Thread(
                    target=client_self.handle_local_client,  # Функция для выполнения в потоке
                    args=(local_client,),  # Только один аргумент - клиентский сокет
                    daemon=True  # Поток-демон (завершается с главным потоком)
                )
                client_thread.start()  # Запуск потока

            # Пропуск итерации при таймауте accept...
            # Нормальная ситуация - нет новых подключений в течение 1 секунды
            except socket.timeout:
                continue  # Продолжаем цикл
            # Обработка других исключений при принятии соединения
            except Exception as e:
                # Логируем ошибку только если сервер ещё работает
                # Чтобы не логировать ошибки, возникающие при нормальном завершении
                if client_self.running:
                    client_self.logger.error(f"Accept error: {e}")

    # Обработка прерывания клавиатуры (Ctrl + C) с информационным сообщением
    # Пользователь нажал Ctrl+C для остановки сервера
    except KeyboardInterrupt:
        client_self.logger.info("Stopping local proxy...")
    # Логирование других ошибок сервера
    except Exception as e:
        client_self.logger.error(f"Local proxy error: {e}")

    # Гарантированное снятие флага и закрытие серверного сокета
    # Выполняется всегда, независимо от того, как был завершён блок try
    finally:
        client_self.running = False  # Снимаем флаг работы
        local_server.close()  # Закрываем серверный сокет
        client_self.logger.info("Local proxy stopped")  # Логируем завершение работы