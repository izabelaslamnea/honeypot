
# HONEYPOT - Sistema de detección y monitorización de amenazas

## Descripción

HONEYPOT es una herramienta de ciberseguridad desarrollada en Python que simula un panel de autenticación administrativo para registrar conexiones, monitorizar intentos de acceso y detectar posibles ataques de fuerza bruta.

El proyecto incorpora una interfaz gráfica que permite visualizar los eventos de seguridad en tiempo real, identificar direcciones IP y generar informes para su posterior análisis.

## Funcionalidades

- **Servidor TCP señuelo:** simula un servicio de autenticación administrativo.
- **Monitorización de conexiones:** registra las conexiones entrantes y los nombres de usuario introducidos.
- **Seguimiento de direcciones IP:** identifica y contabiliza las direcciones IP únicas.
- **Detección de fuerza bruta:** genera alertas al detectar cinco o más intentos fallidos desde una misma IP en un intervalo de dos minutos.
- **Panel de monitorización:** muestra conexiones, IP únicas y alertas de seguridad.
- **Registro de eventos:** almacena los eventos con fecha y hora.
- **Exportación de informes:** permite exportar los registros a archivos CSV.
- **Alertas visuales:** destaca los eventos de amenaza en la interfaz gráfica.

## Interfaz gráfica

El panel de monitorización permite consultar:

- Número total de conexiones.
- Direcciones IP detectadas.
- Alertas de seguridad generadas.
- Eventos registrados en tiempo real.
- Historial de direcciones IP identificadas.

## Tecnologías utilizadas

- Python 3
- Tkinter
- Sockets TCP
- Threading
- Queue
- CSV
- Logging

## Requisitos

- Python 3.10 o superior.

El proyecto utiliza exclusivamente bibliotecas incluidas en la biblioteca estándar de Python, por lo que no requiere instalar dependencias externas.

## Instalación

Clonar el repositorio:

```bash
git clone https://github.com/izabelaslamnea/honeypot.git
```

Acceder al directorio del proyecto:

```bash
cd honeypot
```

## Ejecución

Iniciar el servidor Honeypot y el panel gráfico:

```bash
python honeypot_gui.py
```

En una segunda terminal, ejecutar el cliente de pruebas:

```bash
python client_test.py
```

El cliente realiza cinco intentos de autenticación simulados utilizando credenciales ficticias.

## Detección de ataques

El sistema analiza los intentos de autenticación y los agrupa según la dirección IP de origen.

Cuando una misma dirección IP alcanza cinco intentos fallidos dentro de una ventana temporal de dos minutos, se genera una alerta de posible ataque de fuerza bruta.

## Seguridad y limitaciones

- Proyecto desarrollado con fines educativos y de experimentación en entornos controlados.
- El servidor escucha exclusivamente en la dirección local `127.0.0.1`.
- No implementa un servicio SSH real.
- Las contraseñas introducidas no se almacenan ni se registran en los archivos de log.
- Las pruebas deben realizarse exclusivamente con credenciales ficticias.
- No debe exponerse el servicio a redes públicas.

## Objetivos del proyecto

Este proyecto permite aplicar y desarrollar conocimientos relacionados con:

- Programación de redes.
- Desarrollo de Honeypots.
- Detección de intrusiones.
- Identificación de ataques de fuerza bruta.
- Registro y análisis de eventos de seguridad.
- Desarrollo de herramientas de monitorización similares a las utilizadas en un SOC.

## Autora

Izabela

GitHub: https://github.com/izabelaslamnea
