# -*- coding: utf-8 -*-

# Standard library imports
import sys
import os
import subprocess
import json
import re
import pathlib
import threading
import logging
import time
import datetime
import hashlib
import base64
import lzma
import random
import platform

# From standard library imports
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

# Third-party imports
import requests
import pyfiglet
from colorama import Fore, Style # Imported for security warning
try:
    import cfscrape
except ImportError:
    cfscrape = None # cfscrape is optional

# From third-party imports
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# --- Initial Configurations ---

# Configure stdout for UTF-8
sys.stdout.reconfigure(encoding="utf-8")

# Platform-specific console setup for UTF-8 on Windows
if platform.system() == "Windows":
    os.system("chcp 65001") # Sets Windows console to UTF-8

# Suppress InsecureRequestWarning from requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.captureWarnings(True) # Ensure this is called only once

# --- Status Constants ---
STATUS_ATIVO = "Ativo"
STATUS_INATIVO = "Inativo"
STATUS_NO_CREDENTIALS = "No Credentials in URL"
STATUS_RESPONSE_PARSE_ERROR = "Response Parse Error"
STATUS_TIMEOUT = "Timeout"
STATUS_REQUEST_ERROR = "Request Error"
STATUS_INVALID_URL_FORMAT = "Invalid URL Format"
STATUS_INVALID_URL_NO_NETLOC = "Invalid URL (no netloc)"
STATUS_INATIVO_NO_USERNAME_IN_RESPONSE = "Inativo (no username in response)"
STATUS_UNKNOWN_ERROR = "Unknown Error in verificar_status_m3u"


# --- Global Variables & Constants ---

# Setup cfscrape or default requests session
if cfscrape:
    sesq = requests.Session()
    ses = cfscrape.create_scraper(sess=sesq)
else:
    ses = requests.Session()

# Default SSL Ciphers (if specific configuration is needed)
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMP:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256"

# Default HTTP headers to mimic a specific client for requests.
HEADERS = {
    "Cookie": "stb_lang=en; timezone=Europe%2FIstanbul;",
    "X-User-Agent": "Model: MAG254; Link: Ethernet",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip, deflate",
    "Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "VLC"
}

DIRETORIO_SAIDA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hits")
BANNER_TEXT = "ALEX" 

# Configuration Suggestion for URLs:
# For greater flexibility, consider loading this list of URLs
# from an external configuration file (e.g., a plain text file
# with one URL per line, or a JSON/YAML file) instead of
# hardcoding them here. This would allow easier modification
# without altering the script's code.
# List of base portal URLs to check against the provided M3U credentials.
URLS_COMPLETAS = [
    "http://catali.mine.nu:33000",
    "http://blast.lat:8080"
]

# --- Function Definitions ---

def install_package(pkg_name):
    """Installs a package if it's not already installed."""
    try:
        __import__(pkg_name)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])

def verificar_status_m3u(link_m3u_to_check, http_headers):
    """
    Verifies the status of an M3U link by checking its associated player API.

    Args:
        link_m3u_to_check (str): The M3U link (usually a get.php link).
        http_headers (dict): Headers to use for the request.

    Returns:
        tuple: (status_string, parsed_username, parsed_password, parsed_host)
               The status_string indicates the outcome of the check (e.g., STATUS_ATIVO).
               parsed_username, parsed_password, and parsed_host may be None if
               parsing or validation fails at certain stages.
    """
    try:
        parsed_url = urlparse(link_m3u_to_check)
    except Exception: 
        return STATUS_INVALID_URL_FORMAT, None, None, None

    parsed_host = parsed_url.hostname
    
    try:
        query_params = parse_qs(parsed_url.query)
        if 'username' not in query_params or 'password' not in query_params:
            if "/player_api.php" not in parsed_url.path : 
                 return STATUS_NO_CREDENTIALS, None, None, parsed_host
            parsed_username_list = query_params.get('username')
            parsed_password_list = query_params.get('password')
            parsed_username = parsed_username_list[0] if parsed_username_list else None
            parsed_password = parsed_password_list[0] if parsed_password_list else None
            if not parsed_username or not parsed_password:
                 return STATUS_NO_CREDENTIALS, None, None, parsed_host
    except (KeyError, IndexError): 
        return STATUS_NO_CREDENTIALS, None, None, parsed_host
    
    parsed_username_list = query_params.get('username')
    parsed_password_list = query_params.get('password')
    parsed_username = parsed_username_list[0] if parsed_username_list else None
    parsed_password = parsed_password_list[0] if parsed_password_list else None


    if not parsed_username or not parsed_password: 
        return STATUS_NO_CREDENTIALS, None, None, parsed_host

    full_url_scheme = parsed_url.scheme if parsed_url.scheme else "http"
    full_url_netloc = parsed_url.netloc

    if not full_url_netloc:
        return STATUS_INVALID_URL_NO_NETLOC, parsed_username, parsed_password, parsed_host

    link_api = f"{full_url_scheme}://{full_url_netloc}/player_api.php?username={parsed_username}&password={parsed_password}"
    link_api_status_check = f"{link_api}&type=m3u"

    try:
        # SECURITY WARNING: verify=False disables SSL certificate verification, making connections vulnerable to MITM attacks.
        response = ses.get(link_api_status_check, headers=http_headers, timeout=3, verify=False)
        data_text = response.text
        
        try:
            data_json = response.json()
            user_info = data_json.get("user_info", {})
            status_val = user_info.get("status")
            if status_val == "Active": # "Active" is a specific value from the API
                return STATUS_ATIVO, parsed_username, parsed_password, parsed_host
            elif status_val: 
                return STATUS_INATIVO, parsed_username, parsed_password, parsed_host
        except (json.JSONDecodeError, AttributeError):
            pass 

        if 'username' in data_text: 
            try:
                if '"status":"Active"' in data_text or '"status": "Active"' in data_text :
                    return STATUS_ATIVO, parsed_username, parsed_password, parsed_host
                elif '"status":' in data_text: 
                    return STATUS_INATIVO, parsed_username, parsed_password, parsed_host 
                else: 
                    return STATUS_RESPONSE_PARSE_ERROR, parsed_username, parsed_password, parsed_host
            except IndexError: 
                return STATUS_RESPONSE_PARSE_ERROR, parsed_username, parsed_password, parsed_host
        else:
            return STATUS_INATIVO_NO_USERNAME_IN_RESPONSE, parsed_username, parsed_password, parsed_host
            
    except requests.exceptions.Timeout:
        return STATUS_TIMEOUT, parsed_username, parsed_password, parsed_host
    except requests.exceptions.RequestException:
        return STATUS_REQUEST_ERROR, parsed_username, parsed_password, parsed_host
    except Exception: 
        return STATUS_UNKNOWN_ERROR, parsed_username, parsed_password, parsed_host


def processar_url(base_url, p_username, p_password, p_output_file, p_headers):
    """
    Processes a base URL to check if the provided credentials are active and writes the URL to an output file if active.

    Args:
        base_url (str): The base URL of the portal to check.
        p_username (str): The username for the portal.
        p_password (str): The password for the portal.
        p_output_file (str): Path to the file where active URLs should be appended.
        p_headers (dict): HTTP headers to use for the verification request.
    """
    novo_link_m3u = f"{base_url}/get.php?username={p_username}&password={p_password}&type=m3u_plus"
    status_interno, _, _, _ = verificar_status_m3u(novo_link_m3u, p_headers)
    
    if status_interno == STATUS_ATIVO:
        print(f"[1m[[92m●[0m [1m][0m [42mURL ACTIVO ENCONTRADO[0m\n[96m{novo_link_m3u}[0m")
        try:
            with open(p_output_file, "a", encoding="utf-8") as file:
                file.write(f"║∘{base_url}\n")
        except IOError as e:
            print(f"Error writing to {p_output_file} in processar_url: {e}")


def animar_progresso():
    """Displays a simple progress animation in the console."""
    animation_chars = ["□■□■□■", "■□■□■□", "□■□■□■", "■□■□■□"]
    idx = 0
    while True: 
        print(f"[1;91m[[0m [1;96m● [0m[1;91m][0m[1;93mVERIFICANDO:   [0m" + animation_chars[idx % len(animation_chars)], end="\r")
        idx +=1
        time.sleep(0.3)

# --- Main Execution ---

def main():
    # Startup Security Warning for verify=False
    print(Fore.YELLOW + Style.BRIGHT + "SECURITY WARNING: This script disables SSL certificate verification for network requests (verify=False). " +
          "This is a potential security risk and should only be used if you understand the implications " +
          "(e.g., trusted network, self-signed certificates). Do not use this script with sensitive URLs on untrusted networks." + 
          Style.RESET_ALL + "\n")

    ascii_banner_main = pyfiglet.figlet_format("ESPEJOS", font="slant")
    print(Fore.BLUE + Style.BRIGHT + ascii_banner_main + Style.RESET_ALL)

    # Dependency Management Suggestion:
    # While this script attempts to auto-install missing packages,
    # for more robust and predictable dependency management, it is
    # recommended to use a `requirements.txt` file.
    # You would typically create a `requirements.txt` file listing
    # all necessary packages (e.g., requests, pyfiglet, colorama, cfscrape)
    # and then install them using: pip install -r requirements.txt
    required_packages = ["requests", "lzma", "cfscrape", "pysocks", "pyfiglet", "colorama"]
    for package_name in required_packages:
        try:
            install_package(package_name)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {package_name}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while trying to install {package_name}: {e}")
            
    print(BANNER_TEXT)
    print("[1m[[93m⚠️ [0m[1m][41m EL ENLACE M3U PROPORCIONADO NO DEBE ESTAR CADUCADO[0m\n")
    link_m3u_input = input("[1m[[93m?[1m][0m[33m INTRODUZCA UN ENLACE M3U:[0m ")

    status_inicial, initial_usuario, initial_senha, initial_host = verificar_status_m3u(link_m3u_input, HEADERS)

    print("[H[J", end="") 
    print(BANNER_TEXT)

    output_file = None  

    if initial_usuario and initial_senha and initial_host:
        os.makedirs(DIRETORIO_SAIDA, exist_ok=True)
        nome_arquivo_com_prefixo = f"Espejos-Alex-⟬{initial_host}⟭"
        output_file_path = os.path.join(DIRETORIO_SAIDA, f"{nome_arquivo_com_prefixo}#Alex.txt")

        if status_inicial == STATUS_ATIVO:
            print("[1m[[92m●[1m][0m [42mURL  ACTIVA[0m\n")
        elif status_inicial == STATUS_INATIVO:
            print("[1m[[92m●[1m][0m [41m INACTIVO [0m\n")
        else:
            print(f"Estado del link M3U ({link_m3u_input}): {status_inicial}\n")

        try:
            with open(output_file_path, "w", encoding="utf-8") as file: 
                # SECURITY NOTE: Credentials (username, password) are stored in plaintext in this output file.
                # Handle this file with caution and ensure its security.
                file.write("╓❪❪❪ ALEX❫❫❫\n")
                file.write(f"║∘ᴅᴏᴍɪɴɪᴏ ➛ http://{initial_host}\n")
                file.write(f"║∘𝕦𝕤𝕦𝕒𝕣𝕚𝕠 ➛ {initial_usuario}\n")
                file.write(f"║∘𝕔𝕝𝕒𝕧𝕖➛ {initial_senha}\n")
                file.write("╠❪ 𝐃𝐧𝐬 ☟︎︎︎ 𝐌𝐞𝐬𝐦𝐨 𝐔𝐬𝐞𝐫 / 𝐏𝐚𝐬𝐬 ❫\n")
            print(f"Información inicial guardada en: {output_file_path}")
            output_file = output_file_path 
        except IOError as e:
            print(f"Error al escribir en el archivo de salida {output_file_path}: {e}")
            output_file = None 

        if output_file: 
            animation_thread = threading.Thread(target=animar_progresso, daemon=True)
            animation_thread.start()

            with ThreadPoolExecutor(max_workers=24) as executor:
                executor.map(lambda u_url: processar_url(u_url, initial_usuario, initial_senha, output_file, HEADERS), URLS_COMPLETAS)
            
            print(" " * 80, end="\r") 

            try:
                with open(output_file, "a", encoding="utf-8") as file:
                    file.write("╚⫸[ alex ]\n")
                print(f"Proceso completado. ARQUIVO SALVO NA PASTA HITS: {output_file}")
            except IOError as e:
                print(f"Error al escribir la marca final en {output_file}: {e}")
        else:
            print("No se procesarán URLs adicionales debido a un error al escribir en el archivo de salida.")
    else:
        print(f"Error: No se pudo obtener usuario, contraseña o host del M3U proporcionado ('{link_m3u_input}'). Estado: {status_inicial}")
        print("No se procesarán más URLs ni se guardará archivo.")

if __name__ == "__main__":
    main()
