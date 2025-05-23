#!/usr/bin/env python3
"""
A network scanning tool that performs port scans (using nmap),
fetches HTTP content from open ports, and performs DNS lookups.
Results are saved to a report file.

Dependencies:
  - nmap: Must be installed and accessible via system PATH.
  - requests: Python library (install via pip: pip install requests).
  - dnspython: Python library (install via pip: pip install dnspython).
"""
import os
import subprocess
import socket
import shutil
import re
import sys
import ipaddress
import json

import dns.resolver # Added for this function
import requests

# --- Cloudflare IP Range Handling Notes ---
# Cloudflare publishes its IP ranges:
# IPv4: https://www.cloudflare.com/ips-v4
# IPv6: https://www.cloudflare.com/ips-v6
# For robust Cloudflare detection, this script should:
# 1. Fetch these lists.
# 2. Parse them (they are simple text files, one IP/CIDR per line).
# 3. Check if a target IP falls within any of these ranges.
# A function like `get_cloudflare_ip_ranges()` could handle this.
# As a fallback or simpler initial version, a curated list might be embedded.
# --- End Notes ---

# Updated CLOUDFLARE_SAMPLE_IP_RANGES as per the new subtask's conceptual structure
CLOUDFLARE_SAMPLE_IP_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "172.64.0.0/13", "104.16.0.0/12" 
] # Note: 104.16.0.0/12 is a very broad range.

COMMON_SUBDOMAIN_PREFIXES = [
    'www', 'mail', 'ftp', 'cpanel', 'dev', 'api', 'test', 'staging', 'portal', 
    'webmail', 'autodiscover', 'vpn', 'm', 'shop', 'blog', 'support', 'docs',
    'admin', 'login', 'remote', 'assets', 'static', 'owa', 'mail2', 'secure',
    'exchange', 'sip', 'lyncdiscover', 'smtp', 'pop', 'imap', 'ns1', 'ns2'
]

SERVICE_PREFIXES = [ # As per task description
    'mail', 'ftp', 'cpanel', 'webmail', 'direct', 'direct-connect', 'ssl', 
    'dns', 'dns1', 'dns2', 'ns', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'admin', 'owa', 'portal'
]

def find_subdomains_common_dns(target_domain):
    print(f"Buscando subdominios comunes para {target_domain} mediante resolución DNS directa...")
    resolved_subdomains = []
    for prefix in COMMON_SUBDOMAIN_PREFIXES:
        full_subdomain = f"{prefix}.{target_domain}"
        try:
            # Resolve the full subdomain to an IP address
            ip_address = socket.gethostbyname(full_subdomain)
            resolved_subdomains.append(f"{full_subdomain} ({ip_address})")
            print(f"  Encontrado (DNS): {full_subdomain} -> {ip_address}")
        except socket.gaierror:
            # Subdomain does not resolve or does not have an A record, ignore silently
            # print(f"  No encontrado (DNS): {full_subdomain}") # Optional: for debugging
            pass
        except Exception as e:
            # Catch any other unexpected errors for a specific lookup to allow the loop to continue
            print(f"  Error inesperado al resolver {full_subdomain} vía DNS: {e}")
            pass 
    
    if not resolved_subdomains:
        print(f"No se encontraron subdominios comunes para {target_domain} mediante resolución DNS directa.")
    else:
        print(f"Encontrados {len(resolved_subdomains)} subdominios para {target_domain} mediante resolución DNS directa.")
        
    return resolved_subdomains

def check_cloudflare(target_domain_or_ip):
    results = {'is_cloudflare': False, 'evidence': [], 'ip_addresses': []}
    processed_ips_for_http_check = set() # To avoid checking the same IP multiple times

    # 1. Resolve IP if domain, or use if already an IP
    # Try to parse as an IP first
    is_input_ip = False
    try:
        ip_obj = ipaddress.ip_address(target_domain_or_ip)
        results['ip_addresses'].append(str(ip_obj))
        processed_ips_for_http_check.add(str(ip_obj))
        is_input_ip = True
        print(f"'{target_domain_or_ip}' es una IP. Añadida para análisis de Cloudflare.")
    except ValueError:
        # Not an IP, so assume it's a domain name
        print(f"'{target_domain_or_ip}' no es una IP. Intentando resolución DNS para análisis de Cloudflare...")
        try:
            # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            _, _, ipaddrlist = socket.gethostbyname_ex(target_domain_or_ip)
            if ipaddrlist:
                results['ip_addresses'] = list(set(ipaddrlist)) # Remove duplicates
                processed_ips_for_http_check.update(results['ip_addresses'])
                print(f"Dominio '{target_domain_or_ip}' resuelto a IPs para análisis de Cloudflare: {results['ip_addresses']}")
            else:
                results['evidence'].append(f"Resolución DNS para '{target_domain_or_ip}' no devolvió IPs.")
                print(f"Resolución DNS para '{target_domain_or_ip}' no devolvió IPs.")
                return results # No IPs to check
        except socket.gaierror as e:
            results['evidence'].append(f"Fallo en resolución DNS para '{target_domain_or_ip}': {e}")
            print(f"Fallo en resolución DNS para '{target_domain_or_ip}': {e}")
            return results # No IPs to check

    if not results['ip_addresses']:
        results['evidence'].append(f"No se encontraron o resolvieron IPs para '{target_domain_or_ip}'.")
        print(f"No se encontraron o resolvieron IPs para '{target_domain_or_ip}'.")
        return results

    # 2. HTTP Header checks
    # Determine Host header: use the original domain if it was a domain, else the IP itself
    host_header_val = target_domain_or_ip if not is_input_ip else results['ip_addresses'][0]

    for ip_to_check in processed_ips_for_http_check:
        try:
            url_to_check = f"http://{ip_to_check}" # Check on port 80
            # Use a specific Host header if the original target was a domain
            # This is important for sites hosted on shared IPs (like Cloudflare)
            current_headers = {'Host': host_header_val, 'User-Agent': 'CloudflareChecker/1.0'}
            
            print(f"Consultando encabezados HTTP de {url_to_check} (Host: {host_header_val})...")
            # verify=False for cases where direct IP access might have SSL issues (though we use HTTP here)
            response = requests.get(url_to_check, headers=current_headers, timeout=5, allow_redirects=True, verify=False)
            
            server_header = response.headers.get('Server', '').lower()
            if 'cloudflare' in server_header:
                results['is_cloudflare'] = True
                results['evidence'].append(f"IP {ip_to_check}: Servidor HTTP se identifica como 'cloudflare' (Server: {response.headers.get('Server')}).")
            if 'CF-RAY' in response.headers:
                results['is_cloudflare'] = True
                results['evidence'].append(f"IP {ip_to_check}: Encabezado 'CF-RAY' ({response.headers.get('CF-RAY')}) presente.")
            
            # Check for common Cloudflare cookies
            cf_cookies = {'__cfduid', '__cflb', 'cf_clearance'}
            found_cf_cookie = False
            for cookie in response.cookies:
                if cookie.name in cf_cookies:
                    found_cf_cookie = True
                    break
            if found_cf_cookie:
                results['is_cloudflare'] = True
                results['evidence'].append(f"IP {ip_to_check}: Cookie relacionada con Cloudflare encontrada.")

            expect_ct = response.headers.get('Expect-CT', '').lower()
            if 'cloudflare' in expect_ct:
                results['is_cloudflare'] = True
                results['evidence'].append(f"IP {ip_to_check}: Encabezado 'Expect-CT' menciona Cloudflare.")

        except requests.exceptions.RequestException as e:
            # Log error but continue if other IPs are available
            msg = f"IP {ip_to_check}: Error al conectar para revisión de encabezados HTTP: {type(e).__name__}."
            results['evidence'].append(msg)
            print(msg)

    # 3. IP Range checks
    for ip_str in results['ip_addresses']:
        try:
            current_ip_obj = ipaddress.ip_address(ip_str)
            for cidr_str in CLOUDFLARE_SAMPLE_IP_RANGES:
                network_obj = ipaddress.ip_network(cidr_str, strict=False)
                if current_ip_obj in network_obj:
                    results['is_cloudflare'] = True
                    results['evidence'].append(f"IP {ip_str} se encuentra en el rango conocido de Cloudflare {cidr_str}.")
                    break 
        except ValueError as e: # Should not happen if IP was validated by ipaddress.ip_address earlier
            results['evidence'].append(f"Error al procesar la IP {ip_str} para la verificación de rango: {e}")
            print(f"Error al procesar la IP {ip_str} para la verificación de rango: {e}")
            
    if not results['evidence'] and not results['is_cloudflare']: # Add a note if no positive indicators found
        results['evidence'].append(f"No se encontraron indicadores específicos de Cloudflare para '{target_domain_or_ip}'.")

    return results

def find_subdomains_ct(target_domain):
    print(f"Buscando subdominios para {target_domain} usando Certificate Transparency logs (crt.sh)...")
    found_subdomains = set()
    url = f"https://crt.sh/?q=%.{target_domain}&output=json"
    headers = {'User-Agent': 'Python Security Scanner Script/1.0'}

    try:
        response = requests.get(url, headers=headers, timeout=20) # Increased timeout for crt.sh

        if response.status_code == 200:
            try:
                # Ensure response text is not empty before trying to parse
                if not response.text:
                    print("Respuesta de crt.sh vacía.")
                    return []
                
                certificates = response.json()
                
                for cert in certificates:
                    names_to_check = []
                    if 'name_value' in cert:
                        names_to_check.extend(cert['name_value'].split('\n'))
                    if 'common_name' in cert:
                        names_to_check.append(cert['common_name'])
                    
                    for name in names_to_check:
                        name = name.strip().lower()
                        # Filter out empty names, wildcards, and names not belonging to the target domain
                        if name and \
                           (name == target_domain or name.endswith("." + target_domain)) and \
                           not name.startswith('*.'):
                            found_subdomains.add(name)
            except json.JSONDecodeError:
                print(f"Error al decodificar la respuesta JSON de crt.sh para {target_domain}. Contenido: {response.text[:200]}...") # Log first 200 chars
                return [] # Return empty list on JSON error
            except Exception as e: # Catch any other unexpected errors during parsing
                print(f"Error inesperado al procesar certificados de crt.sh para {target_domain}: {e}")
                return []
        else:
            print(f"Error al consultar crt.sh para {target_domain}. Código de estado: {response.status_code}")
            return [] # Return empty list on non-200 status

    except requests.exceptions.RequestException as e:
        print(f"Error de conexión al contactar crt.sh para {target_domain}: {e}")
        return [] # Return empty list on request exception
    
    if not found_subdomains:
        print(f"No se encontraron subdominios directos para {target_domain} a través de crt.sh.")
    else:
        print(f"Encontrados {len(found_subdomains)} subdominios para {target_domain} vía crt.sh.")
        
    return list(found_subdomains)

def find_origin_ip_dns_history(target_domain, api_key_securitytrails):
    print(f"Buscando IP de origen para {target_domain} usando historial DNS (SecurityTrails)...")
    potential_origins = set()

    if not api_key_securitytrails:
        print("  API key de SecurityTrails no proporcionada. Omitiendo esta comprobación.")
        return []

    headers = {
        'APIKEY': api_key_securitytrails,
        'User-Agent': 'Python Security Scanner Script/1.0' # Added version
    }
    url = f"https://api.securitytrails.com/v1/history/{target_domain}/dns/a"

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status() # Raises HTTPError for bad responses (4XX or 5XX)
        
        data = response.json()
        
        # Based on common SecurityTrails structure for /history/{domain}/dns/{type}
        records_list = data.get('records', [])
        if not isinstance(records_list, list): # Ensure records_list is a list
            print(f"  Respuesta inesperada de SecurityTrails: la clave 'records' no es una lista. Data: {str(data)[:200]}")
            return []

        for record in records_list:
            if not isinstance(record, dict): # Ensure each record is a dictionary
                print(f"  Registro inesperado en SecurityTrails (no es un diccionario): {str(record)[:100]}")
                continue

            # The conceptual structure suggests 'ip' is directly in the record.
            # Other ST endpoints might have it under 'values': [{'ip': 'x.x.x.x'}]
            # We will try to get 'ip' directly. If not found, we can check 'values' as a fallback.
            ip_val = record.get('ip')
            
            # Fallback: if 'ip' is not direct, check if 'values' is a list of dicts with 'ip'
            if not ip_val and isinstance(record.get('values'), list):
                for value_item in record.get('values', []):
                    if isinstance(value_item, dict) and value_item.get('ip'):
                        # Process this IP. For simplicity, take the first one if multiple in 'values'.
                        ip_val = value_item.get('ip') 
                        break # Process first IP found in values for this record

            if not ip_val: # If still no IP after checking direct and 'values'
                # print(f"  Registro sin IP en SecurityTrails: {str(record)[:100]}") # Optional: for debugging
                continue

            try:
                ip_obj = ipaddress.ip_address(ip_val)
                is_cf_ip = False
                for cf_network_str in CLOUDFLARE_SAMPLE_IP_RANGES:
                    cf_network = ipaddress.ip_network(cf_network_str, strict=False)
                    if ip_obj in cf_network:
                        is_cf_ip = True
                        break
                if not is_cf_ip:
                    potential_origins.add(str(ip_obj))
            except ValueError:
                print(f"  Valor de IP inválido encontrado en el historial DNS de SecurityTrails: {ip_val}")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401: # Unauthorized
            print("  Error: API key de SecurityTrails inválida o no autorizada.")
        elif e.response.status_code == 429: # Rate limit
            print("  Error: Límite de tasa de API de SecurityTrails alcanzado.")
        elif e.response.status_code == 404: # Not Found
             print(f"  Error: Dominio '{target_domain}' no encontrado en SecurityTrails o sin historial de DNS tipo A.")
        else:
            print(f"  Error HTTP al contactar SecurityTrails: {e} (URL: {url})")
    except requests.exceptions.RequestException as e: # Other network errors (timeout, connection error)
        print(f"  Error de red al contactar SecurityTrails: {e} (URL: {url})")
    except json.JSONDecodeError:
        print(f"  Error al decodificar la respuesta JSON de SecurityTrails. Respuesta: {response.text[:200]}...")
    except Exception as e: # Catch-all for other unexpected errors
        print(f"  Error inesperado durante la búsqueda en SecurityTrails: {e}")
        
    if potential_origins:
        print(f"  Posibles IPs de origen (no Cloudflare) encontradas en SecurityTrails: {list(potential_origins)}")
    else:
        print(f"  No se encontraron IPs de origen candidatas (no Cloudflare) en SecurityTrails para {target_domain}.")

    return list(potential_origins)

def check_related_services_dns(target_domain, subdomains_found=None):
    print(f"Buscando IPs de origen para {target_domain} mediante servicios DNS relacionados...")
    potential_origins = set()
    
    # 1. Check common service prefixes
    for prefix in SERVICE_PREFIXES:
        hostname = f"{prefix}.{target_domain}"
        try:
            print(f"  Resolviendo A para: {hostname}")
            answers = dns.resolver.resolve(hostname, 'A')
            for rdata in answers:
                ip_str = rdata.to_text()
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    is_cf_ip = any(ip_obj in ipaddress.ip_network(cf_net, strict=False) for cf_net in CLOUDFLARE_SAMPLE_IP_RANGES)
                    if not is_cf_ip:
                        potential_origins.add(ip_str)
                        print(f"    Posible IP de origen (no Cloudflare): {ip_str} desde {hostname}")
                except ValueError:
                    print(f"    Valor de IP inválido: {ip_str} desde {hostname}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.resolver.Timeout:
            print(f"  Timeout al resolver A para {hostname}")
        except Exception as e:
            print(f"  Error inesperado resolviendo A para {hostname}: {e}")

    # 2. Check MX records for the target_domain
    try:
        print(f"  Resolviendo MX para: {target_domain}")
        mx_records = dns.resolver.resolve(target_domain, 'MX')
        for mx_data in mx_records:
            mail_server_hostname = mx_data.exchange.to_text().rstrip('.')
            print(f"    Servidor de correo encontrado: {mail_server_hostname}")
            try:
                print(f"      Resolviendo A para servidor de correo: {mail_server_hostname}")
                answers = dns.resolver.resolve(mail_server_hostname, 'A')
                for rdata in answers:
                    ip_str = rdata.to_text()
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        is_cf_ip = any(ip_obj in ipaddress.ip_network(cf_net, strict=False) for cf_net in CLOUDFLARE_SAMPLE_IP_RANGES)
                        if not is_cf_ip:
                            potential_origins.add(ip_str)
                            print(f"        Posible IP de origen (no Cloudflare): {ip_str} desde {mail_server_hostname}")
                    except ValueError:
                        print(f"        Valor de IP inválido: {ip_str} desde {mail_server_hostname}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.resolver.Timeout:
                print(f"      Timeout al resolver A para {mail_server_hostname}")
            except Exception as e:
                print(f"      Error inesperado resolviendo A para {mail_server_hostname}: {e}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print(f"  No se encontraron registros MX para {target_domain}")
    except dns.resolver.Timeout:
        print(f"  Timeout al resolver MX para {target_domain}")
    except Exception as e:
        print(f"  Error inesperado resolviendo MX para {target_domain}: {e}")
        
    if potential_origins:
        print(f"  Posibles IPs de origen (no Cloudflare) encontradas a través de servicios relacionados: {list(potential_origins)}")
    else:
        print(f"  No se encontraron IPs de origen candidatas (no Cloudflare) a través de servicios DNS relacionados para {target_domain}.")

    return list(potential_origins)

def scan_ports(ip):
    print(f"Escaneando puertos de {ip} con nmap directamente desde subprocess...")

    if shutil.which('nmap') is None:
        print("Error: nmap is not installed or not in PATH. Please install nmap to use port scanning.")
        return []

    try:
        # Comando nmap con escaneo SYN (-sS), T4 timing, sin ping (-Pn), para todos los puertos (--open para mostrar solo abiertos)
        result = subprocess.check_output(
            ['nmap', '-sS', '-T4', '-Pn', '-p-', '--open', ip],
            universal_newlines=True,
            stderr=subprocess.PIPE # Capture stderr for better error reporting
        )

        open_ports = []
        for line in result.splitlines():
            if "/tcp" in line and "open" in line:
                port = line.split('/')[0]
                # Basic validation to ensure port is a number
                if port.isdigit():
                    print(f"Puerto {port}/tcp abierto")
                    open_ports.append(int(port))

        return open_ports

    except FileNotFoundError:
        print("Error: nmap command not found. Please ensure nmap is installed and in your system's PATH.")
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error during nmap scan: {e}. Nmap output: {e.stderr}")
        return []

def check_reachability_with_ping(target_ip, report_file_handle):
    print(f"Intentando hacer ping a {target_ip}...")
    report_file_handle.write(f"--- Resultados del Ping a {target_ip} ---\n")
    try:
        # Ping with 1 packet (-c 1), 2-second timeout for reply (-W 2)
        ping_output = subprocess.check_output(
            ["ping", "-c", "1", "-W", "2", target_ip],
            universal_newlines=True,
            timeout=5,  # Overall timeout for the subprocess call
            stderr=subprocess.PIPE
        )
        
        canonical_name_found = None
        for line in ping_output.splitlines():
            # Typical PING output: PING google.com (142.250.184.174) 56(84) bytes of data.
            if "PING" in line and "(" in line and ")" in line: 
                try:
                    # Extract the name from "PING name (ip)"
                    potential_name = line.split('(')[0].split()[1]
                    if potential_name != target_ip: 
                        canonical_name_found = potential_name
                        break
                except IndexError:
                    pass # Line format not as expected, ignore

        if canonical_name_found:
            message = f"Ping a {target_ip} (resolvió a {canonical_name_found}) exitoso.\n"
            print(f"Ping a {target_ip} (resolvió a {canonical_name_found}) exitoso.")
        else:
            message = f"Ping a {target_ip} exitoso.\n"
            print(f"Ping a {target_ip} exitoso.")
        report_file_handle.write(message)
        report_file_handle.write("Salida completa del ping:\n" + ping_output + "\n")

    except subprocess.CalledProcessError as e:
        message = f"No se pudo hacer ping a {target_ip} (Respuesta no exitosa).\n"
        if e.stderr:
            message += f"Error de ping: {e.stderr}\n"
        print(f"No se pudo hacer ping a {target_ip}.")
        report_file_handle.write(message)
    except FileNotFoundError:
        message = f"Comando 'ping' no encontrado. No se pudo verificar la alcanzabilidad para {target_ip}.\n"
        print("Error: Comando 'ping' no encontrado.")
        report_file_handle.write(message)
    except subprocess.TimeoutExpired:
        message = f"Ping a {target_ip} timed out.\n"
        print(f"Ping a {target_ip} timed out.")
        report_file_handle.write(message)
    report_file_handle.write("--- Fin de Resultados del Ping ---\n\n")

def get_dns_records(dominio):
    try:
        print(f"Realizando consulta DNS para {dominio}...")
        ip_address = socket.gethostbyname(dominio)
        print(f"Dirección IP para {dominio}: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"No se pudo encontrar registros DNS para {dominio}. Verifica que el nombre de dominio sea correcto y que tengas conexión a internet.")
        return None

def fetch_http_content(target_ip_for_request, port, path_segment, report_file_handle):
    # Ensure path_segment starts with a slash if it's not empty
    if not path_segment.startswith('/') and path_segment:
        path_segment = '/' + path_segment
    elif not path_segment: # Handle empty path_segment, default to '/'
        path_segment = '/'

    url = f'http://{target_ip_for_request}:{port}{path_segment}'
    try:
        print(f"Haciendo petición HTTP a {url}...")
        response = requests.get(url, timeout=5, allow_redirects=True)

        # Sanitize the path_segment for filename creation
        # Remove leading slash for filename part if path_segment was '/'
        safe_filename_base = re.sub(r'[^\w\.-]', '_', path_segment.strip('/'))
        if not safe_filename_base: 
            safe_filename_base = 'index' # Default for root path
        
        filename = f"{safe_filename_base}_{port}.txt"
            
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"URL Solicitada: {url}\n")
            f.write(f"Código de Estado: {response.status_code}\n")
            f.write("Encabezados de Respuesta:\n")
            for key, value in response.headers.items():
                f.write(f"  {key}: {value}\n")
            f.write("\nContenido de la Respuesta:\n")
            f.write(response.text)
        
        success_message = f"Petición HTTP a {url} realizada (código {response.status_code}). Archivo guardado en {filename}."
        print(success_message)
        report_file_handle.write(success_message + "\n")
        return url # Return the actual URL fetched

    except requests.RequestException as e:
        error_message = f"Error durante la petición HTTP a {url}: {e}"
        print(error_message)
        report_file_handle.write(error_message + "\n")
    return None

# Main execution block
if __name__ == '__main__':
    ip_input = input("Ingrese la dirección IP o el dominio que desea escanear: ")

    # --- Configuration for Optional Features ---
    # Placeholder for SecurityTrails API Key input
    securitytrails_api_key_dummy = "" # Intentionally empty for now, as input is commented
    # securitytrails_api_key = input("Enter your SecurityTrails API key (optional, press Enter to skip): ").strip()
    # if not securitytrails_api_key:
    #     print("SecurityTrails API key not provided. Features requiring it will be skipped.")
    # else:
    #     securitytrails_api_key_dummy = securitytrails_api_key # Use the real key if provided
    # --- End Configuration ---

    if not ip_input.strip():
        print("Error: El input no puede estar vacío. Por favor, ingrese una IP o dominio válido.")
        sys.exit(1)
    
    target_ip_for_scan = ""
    dominio_for_report = ip_input.strip()  # Use stripped input for reporting and filename base

    # Determine if input is an IP address or a hostname
    is_ip_address = False
    try:
        socket.inet_aton(dominio_for_report)  # Validates IPv4
        is_ip_address = True
    except socket.error:
        # Not a valid IPv4 address, assume it's a hostname or invalid
        # Further check for other IP formats (like IPv6) could be added here if needed
        pass

    if is_ip_address:
        print(f"Input '{dominio_for_report}' es una dirección IP.")
        target_ip_for_scan = dominio_for_report
        resolved_ip = None # No DNS resolution needed for IP input itself
    else: # Input is potentially a hostname
        print(f"Input '{dominio_for_report}' parece ser un nombre de host. Intentando resolución DNS...")
        resolved_ip = get_dns_records(dominio_for_report)
        if not resolved_ip:
            print(f"Error: Fallo en la resolución DNS para '{dominio_for_report}'. El script no puede continuar.")
            sys.exit(1)
        else:
            print(f"Nombre de host '{dominio_for_report}' resuelto a IP: {resolved_ip}")
            target_ip_for_scan = resolved_ip
    
    # Proceed only if we have a valid target_ip_for_scan
    if not target_ip_for_scan:
        print("Error: No se pudo determinar una IP válida para escanear. Saliendo.")
        sys.exit(1)

    # Subdomain search (only if the original input was not an IP)
    all_discovered_subdomains = set()
    subdomains_found_ct_results = [] 
    subdomains_found_dns_results = [] 
    potential_origin_ips_history = []
    potential_origin_ips_services = []
    all_discovered_subdomains = set() # Moved initialization here

    if not is_ip_address: # Only search subdomains and DNS history if input was a domain name
        print(f"\n--- Buscando subdominios para '{dominio_for_report}' vía crt.sh ---")
        subdomains_found_ct_results = find_subdomains_ct(dominio_for_report)
        if subdomains_found_ct_results:
            print("Subdominios encontrados (crt.sh):")
            for sub in subdomains_found_ct_results:
                print(f"  - {sub}")
                all_discovered_subdomains.add(sub) # Add to the set for deduplication
        else:
            print(f"No se encontraron subdominios para '{dominio_for_report}' vía crt.sh.")
        print("--- Fin de la búsqueda de subdominios vía crt.sh ---\n")

        print(f"\n--- Buscando subdominios comunes para '{dominio_for_report}' vía DNS ---")
        subdomains_found_dns_results = find_subdomains_common_dns(dominio_for_report)
        if subdomains_found_dns_results:
            print("Subdominios comunes encontrados (DNS):")
            for sub_ip_pair in subdomains_found_dns_results:
                print(f"  - {sub_ip_pair}")
                try:
                    # Extract just the domain part for the consolidated list
                    subdomain_part = sub_ip_pair.split(' ')[0]
                    all_discovered_subdomains.add(subdomain_part)
                except IndexError:
                    print(f"Advertencia: No se pudo extraer el subdominio de '{sub_ip_pair}'")
        else:
            print(f"No se encontraron subdominios comunes para '{dominio_for_report}' vía DNS.")
        print("--- Fin de la búsqueda de subdominios comunes vía DNS ---\n")

        # Find potential origin IPs from DNS history
        print(f"\n--- Buscando IPs de origen (historial DNS) para '{dominio_for_report}' vía SecurityTrails ---")
        # Pass the dummy API key for now
        potential_origin_ips_history = find_origin_ip_dns_history(dominio_for_report, securitytrails_api_key_dummy) 
        if potential_origin_ips_history:
            print(f"IPs de origen potenciales (no Cloudflare) encontradas para '{dominio_for_report}': {potential_origin_ips_history}")
        else:
            print(f"No se encontraron IPs de origen potenciales (no Cloudflare) para '{dominio_for_report}' vía SecurityTrails.")
        print("--- Fin de la búsqueda de IPs de origen (historial DNS) ---\n")

        # Find potential origin IPs from related services DNS
        print(f"\n--- Buscando IPs de origen (servicios relacionados DNS) para '{dominio_for_report}' ---")
        # Pass subdomains_found_ct_results in case it's useful in a more advanced version, though not used now
        potential_origin_ips_services = check_related_services_dns(dominio_for_report, subdomains_found_ct_results) 
        if potential_origin_ips_services:
            print(f"IPs de origen potenciales (no Cloudflare) de servicios DNS relacionados para '{dominio_for_report}': {potential_origin_ips_services}")
        else:
            print(f"No se encontraron IPs de origen potenciales (no Cloudflare) para '{dominio_for_report}' vía servicios DNS relacionados.")
        print("--- Fin de la búsqueda de IPs de origen (servicios relacionados DNS) ---\n")
    
    # Check for Cloudflare
    # This check is performed for both IP and domain inputs.
    print(f"\n--- Verificando Cloudflare para '{dominio_for_report}' ---")
    cloudflare_results = check_cloudflare(dominio_for_report) 
    print(f"Resultado de la verificación de Cloudflare: {'Sí' if cloudflare_results['is_cloudflare'] else 'No'}")
    if cloudflare_results['evidence']:
        print("Evidencia de Cloudflare:")
        for ev in cloudflare_results['evidence']:
            print(f"  - {ev}")
    print("--- Fin de la Verificación de Cloudflare ---\n")

    # If Cloudflare is detected and input was a domain, try to find origin IPs
    consolidated_potential_origin_ips = set()
    if not is_ip_address and cloudflare_results.get('is_cloudflare'):
        print("\n[INFO] Cloudflare detectado. Intentando encontrar IPs de origen...")
        # The individual functions (find_origin_ip_dns_history, check_related_services_dns) 
        # are already called above and print their own detailed console output.
        # Here, we just consolidate their results.
        if potential_origin_ips_history:
            consolidated_potential_origin_ips.update(potential_origin_ips_history)
        if potential_origin_ips_services:
            consolidated_potential_origin_ips.update(potential_origin_ips_services)
        
        if consolidated_potential_origin_ips:
            print(f"\n[INFO] IPs de origen potenciales consolidadas (no Cloudflare): {sorted(list(consolidated_potential_origin_ips))}")
        else:
            print("\n[INFO] No se encontraron IPs de origen potenciales adicionales a través de historial DNS o servicios relacionados.")
    elif not is_ip_address and not cloudflare_results.get('is_cloudflare'):
        print("\n[INFO] Cloudflare no detectado. La búsqueda de IP de origen específica para Cloudflare no es necesaria.")
    elif is_ip_address and cloudflare_results.get('is_cloudflare'):
         print("\n[INFO] Cloudflare detectado, pero el objetivo es una IP. La búsqueda de IP de origen no aplica directamente.")
    else: # IP input, no Cloudflare
        print("\n[INFO] Cloudflare no detectado para la IP proporcionada.")


    # Sanitize the original input (domain or IP) for use in the main report filename
    safe_report_name_base = re.sub(r'[^\w\.-]', '_', dominio_for_report)
    nombre_archivo_reporte_principal = f"reporte_{safe_report_name_base}.txt"
    print(f"El informe principal se guardará en: {nombre_archivo_reporte_principal}")

    try:
        with open(nombre_archivo_reporte_principal, 'w', encoding='utf-8') as f_reporte_principal:
            f_reporte_principal.write(f"Resultados del escaneo para '{dominio_for_report}' (IP escaneada: {target_ip_for_scan}):\n\n")

            # Log DNS resolution details if input was a hostname
            if not is_ip_address and resolved_ip:
                f_reporte_principal.write(f"--- Resultados de la Resolución DNS para '{dominio_for_report}' ---\n")
                f_reporte_principal.write(f"Nombre de host '{dominio_for_report}' resuelto a IP: {resolved_ip}\n")
                f_reporte_principal.write("--- Fin de Resultados de la Resolución DNS ---\n\n")

            # Log Cloudflare check results to the main report
            f_reporte_principal.write(f"--- Resultados de la Verificación de Cloudflare para '{dominio_for_report}' ---\n")
            f_reporte_principal.write(f"¿Detrás de Cloudflare?: {'Sí' if cloudflare_results['is_cloudflare'] else 'No'}\n")
            if cloudflare_results['ip_addresses']:
                 f_reporte_principal.write(f"IPs analizadas para Cloudflare: {', '.join(cloudflare_results['ip_addresses'])}\n")
            if cloudflare_results['evidence']:
                f_reporte_principal.write("Evidencia de Cloudflare:\n")
                for ev in cloudflare_results['evidence']:
                    f_reporte_principal.write(f"  - {ev}\n")
            f_reporte_principal.write("--- Fin de Resultados de la Verificación de Cloudflare ---\n\n")

            # Log Subdomain search results to the main report
            if not is_ip_address: # Only attempt to log if domain was the input
                # Log results from Certificate Transparency
                f_reporte_principal.write(f"--- Resultados de Búsqueda de Subdominios (Certificate Transparency) para '{dominio_for_report}' ---\n")
                if subdomains_found_ct_results:
                    for sub in subdomains_found_ct_results:
                        f_reporte_principal.write(f"  - {sub}\n")
                else:
                    f_reporte_principal.write("No se encontraron subdominios vía Certificate Transparency.\n")
                f_reporte_principal.write("--- Fin de la Búsqueda de Subdominios (crt.sh) ---\n\n")

                # Log results from Common DNS Brute-force
                f_reporte_principal.write(f"--- Resultados de Búsqueda de Subdominios Comunes (DNS) para '{dominio_for_report}' ---\n")
                if subdomains_found_dns_results:
                    for sub_ip_pair in subdomains_found_dns_results:
                        f_reporte_principal.write(f"  - {sub_ip_pair}\n") # Log with IP for this section
                else:
                    f_reporte_principal.write("No se encontraron subdominios comunes vía DNS directo.\n")
                f_reporte_principal.write("--- Fin de la Búsqueda de Subdominios Comunes (DNS) ---\n\n")

                # Log potential origin IPs from DNS history
                f_reporte_principal.write(f"--- IPs de Origen Potenciales (Historial DNS - SecurityTrails) para '{dominio_for_report}' ---\n")
                if potential_origin_ips_history:
                    for ip_hist in potential_origin_ips_history:
                        f_reporte_principal.write(f"  - {ip_hist}\n")
                else:
                    f_reporte_principal.write("No se encontraron IPs de origen potenciales (no Cloudflare) vía SecurityTrails, o la comprobación fue omitida (sin API key).\n")
                f_reporte_principal.write("--- Fin de Búsqueda de IPs de Origen (Historial DNS) ---\n\n")

                # Log potential origin IPs from related services DNS
                f_reporte_principal.write(f"--- IPs de Origen Potenciales (Servicios Relacionados DNS) para '{dominio_for_report}' ---\n")
                if potential_origin_ips_services:
                    for ip_serv in potential_origin_ips_services:
                        f_reporte_principal.write(f"  - {ip_serv}\n")
                else:
                    f_reporte_principal.write("No se encontraron IPs de origen potenciales (no Cloudflare) vía servicios DNS relacionados.\n")
                f_reporte_principal.write("--- Fin de Búsqueda de IPs de Origen (Servicios Relacionados DNS) ---\n\n")

                # Consolidated Origin IPs (if Cloudflare was detected)
                if cloudflare_results.get('is_cloudflare'):
                    f_reporte_principal.write(f"--- Lista Consolidada de IPs de Origen Potenciales (No Cloudflare) para '{dominio_for_report}' ---\n")
                    sorted_consolidated_ips = sorted(list(consolidated_potential_origin_ips))
                    if sorted_consolidated_ips:
                        f_reporte_principal.write(f"Total de IPs de origen potenciales únicas encontradas: {len(sorted_consolidated_ips)}\n")
                        for ip_origin in sorted_consolidated_ips:
                            f_reporte_principal.write(f"  - {ip_origin} (Candidata para investigación adicional)\n")
                    else:
                        f_reporte_principal.write("No se encontraron IPs de origen potenciales (no Cloudflare) a través de los métodos combinados.\n")
                    f_reporte_principal.write("--- Fin de Lista Consolidada de IPs de Origen ---\n\n")
                else:
                    f_reporte_principal.write(f"--- Búsqueda de IP de Origen para '{dominio_for_report}' ---\n")
                    f_reporte_principal.write("Cloudflare no fue detectado, por lo que la búsqueda específica de IP de origen no fue realizada.\n")
                    f_reporte_principal.write("--- Fin de Búsqueda de IP de Origen ---\n\n")
                
                # Now the consolidated list
                sorted_unique_subdomains = sorted(list(all_discovered_subdomains))
                
                f_reporte_principal.write(f"--- Lista Consolidada de Subdominios Únicos Descubiertos para '{dominio_for_report}' ---\n")
                if sorted_unique_subdomains: # This list currently only contains subdomains, not origin IPs
                    f_reporte_principal.write(f"Total de subdominios únicos encontrados (crt.sh + DNS común): {len(sorted_unique_subdomains)}\n")
                    for sub in sorted_unique_subdomains:
                        f_reporte_principal.write(f"  - {sub}\n")
                    print(f"\n[INFO] Se encontraron {len(sorted_unique_subdomains)} subdominios únicos para {dominio_for_report} (excluyendo IPs de historial).")
                else:
                    f_reporte_principal.write(f"No se descubrieron subdominios adicionales para '{dominio_for_report}' a través de los métodos de enumeración.\n")
                    print(f"\n[INFO] No se descubrieron subdominios adicionales para '{dominio_for_report}'.")
                f_reporte_principal.write("--- Fin de Lista Consolidada de Subdominios ---\n\n")
            
            # Check reachability with ping
            check_reachability_with_ping(target_ip_for_scan, f_reporte_principal)
            
            # Perform Nmap port scan
            f_reporte_principal.write("--- Resultados del Escaneo de Puertos con Nmap ---\n")
            open_ports = scan_ports(target_ip_for_scan)
            if open_ports:
                f_reporte_principal.write(f"Puertos abiertos encontrados en {target_ip_for_scan}:\n")
                for port in open_ports:
                    f_reporte_principal.write(f"  {port}/tcp - Abierto\n")
                print(f"Puertos abiertos en {target_ip_for_scan} (objetivo original: {dominio_for_report}): {open_ports}")
                
                # Fetch HTTP content from common web ports found open
                f_reporte_principal.write("\n--- Intentando obtener contenido HTTP de puertos abiertos ---\n")
                paths_to_check = ["/", "/robots.txt", "/sitemap.xml"] # Common paths
                for port_num in open_ports:
                    if port_num == 80 or port_num == 443 or port_num >= 8000: # Common HTTP/S or alternative web ports
                        for path_segment in paths_to_check:
                            print(f"Intentando obtener contenido HTTP de {target_ip_for_scan}:{port_num}{path_segment} (para {dominio_for_report})...")
                            # fetch_http_content's first argument is the IP to connect to.
                            # It saves files like 'index_80.txt', 'robots.txt_80.txt' etc.
                            fetch_http_content(target_ip_for_scan, port_num, path_segment, f_reporte_principal)
            else:
                message = f"No se encontraron puertos abiertos o hubo un error durante el escaneo en {target_ip_for_scan} (objetivo original: {dominio_for_report}).\n"
                f_reporte_principal.write(message)
                print(message.strip())
            f_reporte_principal.write("--- Fin de Resultados del Escaneo de Puertos ---\n\n")
            
            f_reporte_principal.write(f"\nEscaneo finalizado. Creado por @kristoteve.\n")
        
        print(f"Escaneo completado. Resultados guardados en {nombre_archivo_reporte_principal}")

    except IOError as e:
        print(f"Error crítico de E/S al manejar el archivo de reporte principal {nombre_archivo_reporte_principal}: {e}")
        print("No se pudieron guardar los resultados del reporte principal.")

    # Placeholder for functions mentioned in the problem description context (if they were to be integrated)
    # def get_server_info(ip):
    #     print(f"Obteniendo información del servidor para {ip}...")
    #     # Dummy implementation
    #     return {"os": "Linux", "version": "Ubuntu 20.04"}

    # def get_software_info(ip):
    #     print(f"Obteniendo información del software para {ip}...")
    #     # Dummy implementation
    #     return {"web_server": "Apache/2.4.41", "cms": "WordPress 5.8"}
    
    print("Script terminado.")
