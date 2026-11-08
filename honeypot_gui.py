
import tkinter as tk
from tkinter import filedialog
import csv
import socket
import threading
import queue
import logging

from datetime import datetime, timedelta
from collections import defaultdict, deque


# ==========================================
# CONFIGURACIÓN
# ==========================================

HOST = "127.0.0.1"
PORT = 2222

BG_COLOR = "#0b1120"
PANEL_COLOR = "#151f32"
GREEN = "#00e676"
WHITE = "#e6edf3"
GRAY = "#8b9bb4"
RED = "#ff5252"

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=2)


# ==========================================
# REGISTRO Y VARIABLES
# ==========================================

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

event_queue = queue.Queue()
event_history = []
history_lock = threading.Lock()

unique_ips = set()
failed_attempts = defaultdict(deque)

total_connections = 0
total_alerts = 0
total_unique_ips = 0


# ==========================================
# FUNCIONES DE EVENTOS
# ==========================================

def add_event(message, event_type="INFO"):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    event = {
        "timestamp": timestamp,
        "type": event_type,
        "message": message
    }

    with history_lock:
        event_history.append(event)

    event_queue.put((timestamp, event_type, message))

    if event_type == "ALERT":
        logging.critical(message)
    else:
        logging.info(message)


def update_statistics():

    connections_value.config(
        text=str(total_connections)
    )

    ips_value.config(
        text=str(total_unique_ips)
    )

    alerts_value.config(
        text=str(total_alerts)
    )


def process_events():

    global total_connections
    global total_alerts
    global total_unique_ips

    while not event_queue.empty():

        timestamp, event_type, message = event_queue.get()

        events_log.config(state="normal")

        events_log.insert(
            "end",
            f"[{timestamp}] [{event_type}] {message}\n"
        )

        if event_type == "ALERT":
            events_log.tag_add(
                "alert",
                "end-2l",
                "end-1l"
            )

        events_log.see("end")
        events_log.config(state="disabled")

        if event_type == "CONNECTION":
            total_connections += 1

        elif event_type == "NEW_IP":
            total_unique_ips += 1
            ips_list.insert("end", message)

        elif event_type == "ALERT":
            total_alerts += 1

        update_statistics()

    root.after(200, process_events)


# ==========================================
# RECEPCIÓN DE DATOS
# ==========================================

def receive_line(client):

    data = bytearray()

    while len(data) < 1024:

        char = client.recv(1)

        if not char or char == b"\n":
            break

        if char != b"\r":
            data.extend(char)

    return data.decode(
        "utf-8",
        errors="replace"
    ).strip()


# ==========================================
# SERVIDOR HONEYPOT
# ==========================================

def honeypot_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    try:

        server.bind((HOST, PORT))
        server.listen(5)

        add_event(
            f"Servidor activo en {HOST}:{PORT}"
        )

        while True:

            client, address = server.accept()

            with client:

                ip = address[0]

                add_event(
                    f"Nueva conexión desde {ip}",
                    "CONNECTION"
                )

                if ip not in unique_ips:

                    unique_ips.add(ip)

                    add_event(
                        ip,
                        "NEW_IP"
                    )

                client.sendall(
                    b"=== SECURE ADMIN PANEL ===\nUsername: "
                )

                username = receive_line(client)

                client.sendall(
                    b"Password: "
                )

                password = receive_line(client)

                # No almacenar ni registrar contraseñas.
                del password

                add_event(
                    f"Usuario introducido: {username} desde {ip}"
                )

                now = datetime.now()

                failed_attempts[ip].append(now)

                while (
                    failed_attempts[ip]
                    and now - failed_attempts[ip][0]
                    > BRUTE_FORCE_WINDOW
                ):
                    failed_attempts[ip].popleft()

                if len(failed_attempts[ip]) >= BRUTE_FORCE_THRESHOLD:

                    attempts = len(failed_attempts[ip])

                    add_event(
                        f"POSIBLE FUERZA BRUTA desde {ip}: "
                        f"{attempts} intentos en 2 minutos",
                        "ALERT"
                    )

                    failed_attempts[ip].clear()

                client.sendall(
                    b"\nAccess denied. Activity recorded.\n"
                )

    except OSError as error:

        add_event(
            f"Error del servidor: {error}",
            "ALERT"
        )

    finally:
        server.close()


# ==========================================
# EXPORTACIÓN CSV
# ==========================================

def export_report():

    with history_lock:
        report_data = list(event_history)

    if not report_data:

        add_event(
            "No hay eventos para exportar."
        )

        return

    filepath = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[
            ("CSV files", "*.csv")
        ],
        initialfile="honeypot_report.csv"
    )

    if not filepath:
        return

    try:

        with open(
            filepath,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "timestamp",
                    "type",
                    "message"
                ]
            )

            writer.writeheader()
            writer.writerows(report_data)

        add_event(
            f"Informe exportado correctamente: {filepath}"
        )

    except OSError as error:

        add_event(
            f"Error al exportar: {error}",
            "ALERT"
        )


# ==========================================
# VENTANA PRINCIPAL
# ==========================================

root = tk.Tk()

root.title(
    "HONEYPOT | Security Operations Center"
)

root.geometry("1100x750")
root.minsize(900, 650)
root.configure(bg=BG_COLOR)


# ==========================================
# ENCABEZADO
# ==========================================

header = tk.Frame(
    root,
    bg=BG_COLOR
)

header.pack(
    fill="x",
    padx=25,
    pady=20
)

tk.Label(
    header,
    text="HONEYPOT",
    font=("Consolas", 25, "bold"),
    fg=GREEN,
    bg=BG_COLOR
).pack(side="left")

tk.Label(
    header,
    text="SECURITY OPERATIONS CENTER",
    font=("Consolas", 11),
    fg=GRAY,
    bg=BG_COLOR
).pack(
    side="left",
    padx=20,
    pady=10
)


# ==========================================
# BARRA DE ACCIONES
# ==========================================

actions_frame = tk.Frame(
    root,
    bg=BG_COLOR
)

actions_frame.pack(
    fill="x",
    padx=25,
    pady=5
)

export_button = tk.Button(
    actions_frame,
    text="EXPORT REPORT",
    command=export_report,
    font=("Consolas", 10, "bold"),
    fg=BG_COLOR,
    bg=GREEN,
    activebackground="#00c853",
    activeforeground=BG_COLOR,
    relief="flat",
    padx=15,
    pady=8,
    cursor="hand2"
)

export_button.pack(side="right")


# ==========================================
# ESTADO DEL SERVIDOR
# ==========================================

status_panel = tk.Frame(
    root,
    bg=PANEL_COLOR
)

status_panel.pack(
    fill="x",
    padx=25,
    pady=10
)

status_label = tk.Label(
    status_panel,
    text="● SERVER STATUS: WAITING",
    font=("Consolas", 12, "bold"),
    fg=GREEN,
    bg=PANEL_COLOR,
    pady=15
)

status_label.pack(
    side="left",
    padx=20
)


# ==========================================
# TARJETAS DE ESTADÍSTICAS
# ==========================================

stats_frame = tk.Frame(
    root,
    bg=BG_COLOR
)

stats_frame.pack(
    fill="x",
    padx=25,
    pady=15
)


def create_stat(parent, title, value):

    card = tk.Frame(
        parent,
        bg=PANEL_COLOR,
        padx=20,
        pady=15
    )

    tk.Label(
        card,
        text=title,
        font=("Consolas", 10),
        fg=GRAY,
        bg=PANEL_COLOR
    ).pack()

    number = tk.Label(
        card,
        text=value,
        font=("Consolas", 25, "bold"),
        fg=GREEN,
        bg=PANEL_COLOR
    )

    number.pack(pady=8)

    return card, number


connections_card, connections_value = create_stat(
    stats_frame,
    "CONNECTIONS",
    "0"
)

ips_card, ips_value = create_stat(
    stats_frame,
    "UNIQUE IPS",
    "0"
)

alerts_card, alerts_value = create_stat(
    stats_frame,
    "THREAT ALERTS",
    "0"
)

for card in (
    connections_card,
    ips_card,
    alerts_card
):

    card.pack(
        side="left",
        expand=True,
        fill="both",
        padx=7
    )


# ==========================================
# PANEL DE IPs DETECTADAS
# ==========================================

ips_frame = tk.Frame(
    root,
    bg=PANEL_COLOR
)

ips_frame.pack(
    fill="x",
    padx=25,
    pady=10
)

tk.Label(
    ips_frame,
    text="DETECTED IP ADDRESSES",
    font=("Consolas", 12, "bold"),
    fg=GREEN,
    bg=PANEL_COLOR
).pack(
    anchor="w",
    padx=15,
    pady=10
)

ips_list = tk.Listbox(
    ips_frame,
    height=3,
    bg="#080d18",
    fg=WHITE,
    font=("Consolas", 10),
    relief="flat"
)

ips_list.pack(
    fill="x",
    padx=15,
    pady=10
)


# ==========================================
# PANEL DE EVENTOS
# ==========================================

events_frame = tk.Frame(
    root,
    bg=PANEL_COLOR
)

events_frame.pack(
    fill="both",
    expand=True,
    padx=25,
    pady=15
)

tk.Label(
    events_frame,
    text="LIVE SECURITY EVENTS",
    font=("Consolas", 13, "bold"),
    fg=GREEN,
    bg=PANEL_COLOR
).pack(
    anchor="w",
    padx=15,
    pady=15
)

events_log = tk.Text(
    events_frame,
    bg="#080d18",
    fg=WHITE,
    font=("Consolas", 10),
    insertbackground=WHITE,
    relief="flat",
    wrap="word"
)

events_log.pack(
    fill="both",
    expand=True,
    padx=15,
    pady=10
)

events_log.tag_config(
    "alert",
    foreground=RED
)

events_log.insert(
    "end",
    "[SYSTEM] Honeypot dashboard initialized.\n"
    "[SYSTEM] Waiting for security events...\n"
)

events_log.config(state="disabled")


# ==========================================
# PIE DE PÁGINA
# ==========================================

tk.Label(
    root,
    text="LOCAL LAB ENVIRONMENT | 127.0.0.1:2222",
    font=("Consolas", 9),
    fg=GRAY,
    bg=BG_COLOR
).pack(pady=10)


# ==========================================
# INICIAR APLICACIÓN
# ==========================================

server_thread = threading.Thread(
    target=honeypot_server,
    daemon=True
)

server_thread.start()

root.after(200, process_events)

root.mainloop()
