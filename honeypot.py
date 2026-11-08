
import socket
import logging
from datetime import datetime
from collections import defaultdict, deque
from datetime import timedelta


HOST = "127.0.0.1"
PORT = 2222

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

# Configuración de detección de fuerza bruta
failed_attempts = defaultdict(deque)

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=2)

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print("====================================")
    print("          HONEYPOT ACTIVE")
    print("====================================")
    print(f"Servidor escuchando en {HOST}:{PORT}")
    print("Esperando conexiones...")
    print("Pulsa CTRL+C para detenerlo.\n")

    try:
        while True:
            client, address = server.accept()

            ip = address[0]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print("------------------------------------")
            print(f"[{timestamp}] Nueva conexión")
            print(f"IP de origen: {ip}")
            logging.info(f"Conexión recibida desde {ip}")

            client.sendall(
                b"=== SECURE ADMIN PANEL ===\n"
                b"Username: "
            )

            username = client.recv(1024).decode(
                "utf-8", errors="replace"
            ).strip()

            client.sendall(b"Password: ")

            password = client.recv(1024).decode(
                "utf-8", errors="replace"
            ).strip()

            print(f"Usuario introducido: {username}")
            logging.info(f"Intento de acceso - IP: {ip} - Usuario: {username}")
            print("Se ha recibido un intento de acceso.")
            logging.warning(f"Acceso rechazado - IP: {ip} - Usuario: {username}")
            # Registrar intento fallido
            now = datetime.now()
            failed_attempts[ip].append(now)

            # Eliminar intentos anteriores a los últimos 2 minutos
            while failed_attempts[ip] and now - failed_attempts[ip][0] > BRUTE_FORCE_WINDOW:
                failed_attempts[ip].popleft()

            # Comprobar posible fuerza bruta
            if len(failed_attempts[ip]) >= BRUTE_FORCE_THRESHOLD:
                alert = (
                    f"POSIBLE FUERZA BRUTA - IP: {ip} - "
                    f"{len(failed_attempts[ip])} intentos en 2 minutos"
                )

                print(f"\n[ALERTA] {alert}")
                logging.critical(alert)

                failed_attempts[ip].clear()

            # No almacenamos la contraseña introducida.
            print("Contraseña: [NO ALMACENADA]")

            client.sendall(
                b"\nAccess denied. Activity recorded.\n"
            )

            client.close()

    except KeyboardInterrupt:
        print("\nDeteniendo el Honeypot...")

    finally:
        server.close()


if __name__ == "__main__":
    start_honeypot()
