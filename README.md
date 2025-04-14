# Bludit-3.9.2-Auth-Bypass

**Bludit Auth Brute Force Mitigation Bypass Script**

Este script de Python está diseñado para realizar ataques de fuerza bruta en la página de inicio de sesión de Bludit (versión <= 3.9.2) y eludir las mitigaciones de fuerza bruta.

## Características

- Realiza ataques de fuerza bruta utilizando diccionarios de usuarios y contraseñas.
- Maneja tokens CSRF dinámicos.
- Muestra barras de progreso para un seguimiento visual del proceso.
- Colores en los mensajes para una mejor legibilidad.

## Requisitos

- Python 3.x
- Bibliotecas adicionales: `requests`, `pwn`, `tqdm`, `colorama`

## Instalación

1. Clona el repositorio:

    ```sh
    git clone https://github.com/tu-usuario/Bludit-BruteForce-Bypass.git
    cd Bludit-BruteForce-Bypass
    ```

2. Instala las dependencias:

    ```sh
    pip install -r requirements.txt
    ```

## Uso

1. Asegúrate de tener los archivos de diccionario de usuarios y contraseñas (`user.txt` y `pass.txt`).

2. Ejecuta el script con los siguientes argumentos:

    ```sh
    python3 definitivo.py -l http://192.168.18.57/admin/login.php -u user.txt -p /usr/share/wordlists/rockyou.txt
    ```

    - `-l` o `--url`: URL de la página de inicio de sesión de Bludit.
    - `-u` o `--userlist`: Ruta al archivo de diccionario de usuarios.
    - `-p` o `--passlist`: Ruta al archivo de diccionario de contraseñas.

## Ejemplo

```sh
python3 Bludit-Auth-Bypass.py -l http://192.168.18.57/admin/login.php -u user.txt -p /usr/share/wordlists/rockyou.txt

![2025-04-14_12-50](https://github.com/user-attachments/assets/5d76e17f-1c01-414c-b52e-cfd343449c79)


