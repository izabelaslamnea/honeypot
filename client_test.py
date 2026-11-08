import socket

HOST = "127.0.0.1"
PORT = 2222


def test_connection():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((HOST, PORT))

            print(client.recv(1024).decode("utf-8"))

            client.sendall(b"admin\n")
            print(client.recv(1024).decode("utf-8"))

            client.sendall(b"Test123!\n")
            print(client.recv(1024).decode("utf-8"))

    except ConnectionRefusedError:
        print("No se pudo conectar al Honeypot.")


if __name__ == "__main__":
    for attempt in range(5):
        print(f"\nIntento de prueba {attempt + 1}/5")
        test_connection()