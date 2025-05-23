#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

# --- Definition of perform_full_scan function ---
def perform_full_scan(target_input, main_report_file_handle, st_api_key, vt_api_key, vd_api_key):
    current_run_results = {}
    dominio_for_report = target_input.strip()
    current_run_results['original_target'] = dominio_for_report

    # Write initial header to the provided file handle
    main_report_file_handle.write(f"\n\n--- Resultados del Escaneo Detallado para '{dominio_for_report}' ---\n")

    # Determine if input is an IP address or a hostname
    is_ip_address_local = False
    resolved_ip_local = None
    target_ip_for_scan_local = ""

    try:
        socket.inet_aton(dominio_for_report)
        is_ip_address_local = True
    except socket.error:
        pass

    if is_ip_address_local:
        print(f"Input '{dominio_for_report}' es una dirección IP.")
        target_ip_for_scan_local = dominio_for_report
    else:
        print(f"Input '{dominio_for_report}' parece ser un nombre de host. Intentando resolución DNS...")
        resolved_ip_local = get_dns_records(dominio_for_report) # Uses existing global get_dns_records
        if not resolved_ip_local:
            message = f"Error: Fallo en la resolución DNS para '{dominio_for_report}'. No se puede continuar el escaneo para este objetivo.\n"
            print(message.strip())
            main_report_file_handle.write(message)
            current_run_results['is_ip_address_input'] = is_ip_address_local
            current_run_results['resolved_ip'] = resolved_ip_local
            current_run_results['target_ip_for_scan'] = None
            main_report_file_handle.write(f"--- Fin del Escaneo Detallado para '{dominio_for_report}' (Fallo Temprano) ---\n\n")
            return current_run_results # Return partially filled results

        print(f"Nombre de host '{dominio_for_report}' resuelto a IP: {resolved_ip_local}")
        target_ip_for_scan_local = resolved_ip_local

    current_run_results['is_ip_address_input'] = is_ip_address_local
    current_run_results['resolved_ip'] = resolved_ip_local
    current_run_results['target_ip_for_scan'] = target_ip_for_scan_local

    # Log DNS resolution details if input was a hostname
    if not is_ip_address_local and resolved_ip_local:
        main_report_file_handle.write(f"--- Resultados de la Resolución DNS para '{dominio_for_report}' ---\n")
        main_report_file_handle.write(f"Nombre de host '{dominio_for_report}' resuelto a IP: {resolved_ip_local}\n")
        main_report_file_handle.write("--- Fin de Resultados de la Resolución DNS ---\n\n")

    # Subdomain search (only if the original input was not an IP)
    all_discovered_subdomains_set_local = set()
    subdomains_found_ct_results_local = []
    subdomains_found_dns_results_local = []
    potential_origin_ips_history_local = []
    potential_origin_ips_services_local = []

    if not is_ip_address_local:
        print(f"\n--- Buscando subdominios para '{dominio_for_report}' vía crt.sh ---")
        subdomains_found_ct_results_local = find_subdomains_ct(dominio_for_report)
        if subdomains_found_ct_results_local:
            for sub in subdomains_found_ct_results_local:
                all_discovered_subdomains_set_local.add(sub)
        main_report_file_handle.write(f"--- Resultados de Búsqueda de Subdominios (Certificate Transparency) para '{dominio_for_report}' ---\n")
        if subdomains_found_ct_results_local:
            for sub in subdomains_found_ct_results_local: main_report_file_handle.write(f"  - {sub}\n")
        else: main_report_file_handle.write("No se encontraron subdominios vía Certificate Transparency.\n")
        main_report_file_handle.write("--- Fin de la Búsqueda de Subdominios (crt.sh) ---\n\n")

        print(f"\n--- Buscando subdominios comunes para '{dominio_for_report}' vía DNS ---")
        subdomains_found_dns_results_local = find_subdomains_common_dns(dominio_for_report)
        if subdomains_found_dns_results_local:
            for sub_ip_pair in subdomains_found_dns_results_local:
                try: subdomain_part = sub_ip_pair.split(' ')[0]; all_discovered_subdomains_set_local.add(subdomain_part)
                except IndexError: pass
        main_report_file_handle.write(f"--- Resultados de Búsqueda de Subdominios Comunes (DNS) para '{dominio_for_report}' ---\n")
        if subdomains_found_dns_results_local:
            for sub_ip_pair in subdomains_found_dns_results_local: main_report_file_handle.write(f"  - {sub_ip_pair}\n")
        else: main_report_file_handle.write("No se encontraron subdominios comunes vía DNS directo.\n")
        main_report_file_handle.write("--- Fin de la Búsqueda de Subdominios Comunes (DNS) ---\n\n")

        current_run_results['all_discovered_subdomains'] = sorted(list(all_discovered_subdomains_set_local))
    else:
        current_run_results['all_discovered_subdomains'] = []

    # Cloudflare Check
    print(f"\n--- Verificando Cloudflare para '{dominio_for_report}' ---")
    cloudflare_results_local = check_cloudflare(dominio_for_report)
    current_run_results['cloudflare_results'] = cloudflare_results_local
    main_report_file_handle.write(f"--- Resultados de la Verificación de Cloudflare para '{dominio_for_report}' ---\n")
    main_report_file_handle.write(f"¿Detrás de Cloudflare?: {'Sí' if cloudflare_results_local.get('is_cloudflare') else 'No'}\n")
    if cloudflare_results_local.get('ip_addresses'): main_report_file_handle.write(f"IPs analizadas para Cloudflare: {', '.join(cloudflare_results_local['ip_addresses'])}\n")
    if cloudflare_results_local.get('evidence'):
        main_report_file_handle.write("Evidencia de Cloudflare:\n")
        for ev in cloudflare_results_local['evidence']: main_report_file_handle.write(f"  - {ev}\n")
    main_report_file_handle.write("--- Fin de Resultados de la Verificación de Cloudflare ---\n\n")

    # Origin IP Search (if not IP)
    consolidated_potential_origin_ips_set_local = set()
    if not is_ip_address_local:
        print(f"\n--- Buscando IPs de origen (historial DNS) para '{dominio_for_report}' vía SecurityTrails ---")
        potential_origin_ips_history_local = find_origin_ip_dns_history(dominio_for_report, st_api_key)
        main_report_file_handle.write(f"--- IPs de Origen Potenciales (Historial DNS - SecurityTrails) para '{dominio_for_report}' ---\n")
        if potential_origin_ips_history_local:
            for ip_hist in potential_origin_ips_history_local: main_report_file_handle.write(f"  - {ip_hist}\n")
        else: main_report_file_handle.write("No se encontraron IPs de origen potenciales vía SecurityTrails o clave no provista.\n")
        main_report_file_handle.write("--- Fin de Búsqueda de IPs de Origen (Historial DNS) ---\n\n")

        print(f"\n--- Buscando IPs de origen (servicios relacionados DNS) para '{dominio_for_report}' ---")
        potential_origin_ips_services_local = check_related_services_dns(dominio_for_report, subdomains_found_ct_results_local)
        main_report_file_handle.write(f"--- IPs de Origen Potenciales (Servicios Relacionados DNS) para '{dominio_for_report}' ---\n")
        if potential_origin_ips_services_local:
            for ip_serv in potential_origin_ips_services_local: main_report_file_handle.write(f"  - {ip_serv}\n")
        else: main_report_file_handle.write("No se encontraron IPs de origen potenciales vía servicios DNS relacionados.\n")
        main_report_file_handle.write("--- Fin de Búsqueda de IPs de Origen (Servicios Relacionados DNS) ---\n\n")

        if cloudflare_results_local.get('is_cloudflare'):
            if potential_origin_ips_history_local: consolidated_potential_origin_ips_set_local.update(potential_origin_ips_history_local)
            if potential_origin_ips_services_local: consolidated_potential_origin_ips_set_local.update(potential_origin_ips_services_local)
            main_report_file_handle.write(f"--- Lista Consolidada de IPs de Origen Potenciales (No Cloudflare) para '{dominio_for_report}' ---\n")
            if consolidated_potential_origin_ips_set_local:
                main_report_file_handle.write(f"Total de IPs de origen potenciales únicas encontradas: {len(consolidated_potential_origin_ips_set_local)}\n")
                for ip_origin in sorted(list(consolidated_potential_origin_ips_set_local)): main_report_file_handle.write(f"  - {ip_origin}\n")
            else: main_report_file_handle.write("No se encontraron IPs de origen potenciales.\n")
            main_report_file_handle.write("--- Fin de Lista Consolidada de IPs de Origen ---\n\n")
        else:
            main_report_file_handle.write(f"--- Búsqueda de IP de Origen para '{dominio_for_report}' ---\n")
            main_report_file_handle.write("Cloudflare no fue detectado, la búsqueda específica de IP de origen no fue realizada.\n")
            main_report_file_handle.write("--- Fin de Búsqueda de IP de Origen ---\n\n")

    current_run_results['consolidated_potential_origin_ips'] = sorted(list(consolidated_potential_origin_ips_set_local))

    # VirusTotal and ViewDNS reports
    current_run_results['virustotal_summary'] = get_virustotal_report(dominio_for_report, vt_api_key, main_report_file_handle)
    current_run_results['viewdns_summary'] = get_viewdns_info(dominio_for_report, vd_api_key, main_report_file_handle)

    # Ping Check
    check_reachability_with_ping(target_ip_for_scan_local, main_report_file_handle)

    # Port Scan
    main_report_file_handle.write("--- Resultados del Escaneo de Puertos con Nmap ---\n")
    open_ports_list_local = scan_ports(target_ip_for_scan_local)
    current_run_results['open_ports'] = open_ports_list_local if open_ports_list_local else []
    if open_ports_list_local:
        main_report_file_handle.write(f"Puertos abiertos encontrados en {target_ip_for_scan_local}:\n")
        for port in open_ports_list_local: main_report_file_handle.write(f"  {port}/tcp - Abierto\n")

        main_report_file_handle.write("\n--- Intentando obtener contenido HTTP de puertos abiertos ---\n")
        paths_to_check = ["/", "/robots.txt", "/sitemap.xml"]
        for port_num in open_ports_list_local:
            if port_num == 80 or port_num == 443 or port_num >= 8000:
                for path_segment in paths_to_check:
                    fetch_http_content(target_ip_for_scan_local, port_num, path_segment, main_report_file_handle)
    else:
        main_report_file_handle.write(f"No se encontraron puertos abiertos o hubo un error durante el escaneo en {target_ip_for_scan_local}.\n")
    main_report_file_handle.write("--- Fin de Resultados del Escaneo de Puertos ---\n\n")

    main_report_file_handle.write(f"\nEscaneo detallado para '{dominio_for_report}' finalizado.\n")
    main_report_file_handle.write(f"--- Fin del Escaneo Detallado para '{dominio_for_report}' ---\n\n")
    return current_run_results
# --- End of perform_full_scan function ---

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

def get_virustotal_report(resource, api_key, report_file_handle):
    print(f"\n--- Obteniendo reporte de VirusTotal para '{resource}' ---")
    report_file_handle.write(f"--- Resultados de VirusTotal para '{resource}' ---\n")

    if not api_key:
        message = "  API key de VirusTotal no proporcionada. Omitiendo esta comprobación.\n"
        print(message.strip())
        report_file_handle.write(message + "\n")
        return message # Return the message to be stored in current_run_results['virustotal_summary']

    base_url = "https://www.virustotal.com/api/v3/"
    headers = {"x-apikey": api_key, "User-Agent": "Python Security Scanner Script/1.0"}
    # This summary will be returned by the function and printed by display_scan_findings
    # It will also be used if an early error occurs.
    console_summary_message = f"  Resumen de VirusTotal para '{resource}':\n"


    is_ip = False
    try:
        ipaddress.ip_address(resource)
        is_ip = True
    except ValueError:
        pass

    # Determine the correct main VirusTotal API endpoint and GUI link based on resource type
    if is_ip:
        url = f"{base_url}ip_addresses/{resource}"
        gui_link = f"https://www.virustotal.com/gui/ip-address/{resource}/relations"
    else: # Domain
        url = f"{base_url}domains/{resource}"
        gui_link = f"https://www.virustotal.com/gui/domain/{resource}/relations" # MODIFIED as per requirement

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status() # Check for HTTP errors

        data = response.json().get('data', {})
        attributes = data.get('attributes', {})

        if not attributes:
            message = f"  No se encontraron atributos en la respuesta de VirusTotal para '{resource}'.\n"
            print(message.strip())
            report_file_handle.write(message + "\n")
            console_summary_message += message # Append to console summary
            return console_summary_message # Return the summary message

        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)

        # Basic summary for console and file
        basic_summary_part = (
            f"  Maliciosos: {malicious}\n"
            f"  Sospechosos: {suspicious}\n"
            f"  Inofensivos: {harmless}\n"
            f"  No detectados: {undetected}\n"
            f"  Enlace al reporte completo (GUI): {gui_link}\n"
        )
        print(basic_summary_part.strip()) # Print basic summary to console
        report_file_handle.write(basic_summary_part + "\n") # Write to report file
        console_summary_message += basic_summary_part # Add to the message to be returned

        # --- Fetch and display Passive DNS Replication (only for domains) ---
        # This data will be added to both the console summary and the report file.
        passive_dns_summary_part_for_console = "" # Specifically for console_summary_message
        if not is_ip: # Passive DNS is typically more relevant for domains
            passive_dns_url = f"{base_url}domains/{resource}/passive_dns"
            passive_dns_report_part_for_file = "--- Passive DNS Replication ---\n" # For file report
            current_passive_dns_console_summary = "  Passive DNS Replication:\n" # Temp var for this section's console output
            try:
                passive_dns_response = requests.get(passive_dns_url, headers=headers, timeout=20)
                passive_dns_response.raise_for_status()
                passive_dns_data = passive_dns_response.json().get('data', [])

                if passive_dns_data:
                    passive_dns_report_part_for_file += "  IPs Históricas (Passive DNS):\n"
                    found_pdns_ips = []
                    for dns_entry in passive_dns_data:
                        ip_addr = dns_entry.get('attributes', {}).get('ip_address', 'N/A')
                        if ip_addr != 'N/A':
                             passive_dns_report_part_for_file += f"    - {ip_addr}\n"
                             found_pdns_ips.append(ip_addr)
                    if found_pdns_ips:
                        for ip_addr_cs in found_pdns_ips:
                            current_passive_dns_console_summary += f"    - {ip_addr_cs}\n"
                    else:
                        no_data_msg = "  No se encontraron IPs válidas en los datos de Passive DNS.\n"
                        passive_dns_report_part_for_file += no_data_msg
                        current_passive_dns_console_summary += no_data_msg
                else:
                    no_data_msg = "  No se encontraron datos de Passive DNS.\n"
                    passive_dns_report_part_for_file += no_data_msg
                    current_passive_dns_console_summary += no_data_msg

            except requests.exceptions.RequestException as e_pdns:
                err_msg_pdns = f"  Error al obtener Passive DNS para '{resource}': {type(e_pdns).__name__}.\n"
                passive_dns_report_part_for_file += err_msg_pdns
                current_passive_dns_console_summary += err_msg_pdns
                print(err_msg_pdns.strip())
            finally:
                report_file_handle.write(passive_dns_report_part_for_file + "\n")
                passive_dns_summary_part_for_console = current_passive_dns_console_summary # Assign to be added to main console summary
                console_summary_message += passive_dns_summary_part_for_console

        # --- Fetch and display Siblings (Subdomains - only for domains) ---
        # This data will be added to both the console summary and the report file.
        siblings_summary_part_for_console = "" # Specifically for console_summary_message
        if not is_ip: # Subdomains are relevant for domains
            siblings_url = f"{base_url}domains/{resource}/subdomains" # Correct endpoint for subdomains
            siblings_report_part_for_file = "--- Subdominios (Siblings) ---\n" # For file report
            current_siblings_console_summary = "  Subdominios (Siblings):\n" # Temp var for this section's console output
            try:
                siblings_response = requests.get(siblings_url, headers=headers, timeout=20)
                siblings_response.raise_for_status()
                siblings_data = siblings_response.json().get('data', [])

                if siblings_data:
                    siblings_report_part_for_file += "  Subdominios Encontrados:\n"
                    found_subdomains = []
                    for sibling_entry in siblings_data:
                        subdomain_id = sibling_entry.get('id', 'N/A')
                        if subdomain_id != 'N/A':
                            siblings_report_part_for_file += f"    - {subdomain_id}\n"
                            found_subdomains.append(subdomain_id)
                    if found_subdomains:
                        for sub_id_cs in found_subdomains:
                            current_siblings_console_summary += f"    - {sub_id_cs}\n"
                    else:
                        no_data_msg = "  No se encontraron IDs de subdominios válidos.\n"
                        siblings_report_part_for_file += no_data_msg
                        current_siblings_console_summary += no_data_msg
                else:
                    no_data_msg = "  No se encontraron subdominios.\n"
                    siblings_report_part_for_file += no_data_msg
                    current_siblings_console_summary += no_data_msg
            except requests.exceptions.RequestException as e_sibl:
                err_msg_sibl = f"  Error al obtener subdominios para '{resource}': {type(e_sibl).__name__}.\n"
                siblings_report_part_for_file += err_msg_sibl
                current_siblings_console_summary += err_msg_sibl
                print(err_msg_sibl.strip())
            finally:
                report_file_handle.write(siblings_report_part_for_file + "\n")
                siblings_summary_part_for_console = current_siblings_console_summary # Assign to be added to main console summary
                console_summary_message += siblings_summary_part_for_console

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            message = "  Error: Clave API de VirusTotal inválida o no autorizada.\n"
        elif e.response.status_code == 429:
            message = "  Error: Límite de tasa de API de VirusTotal alcanzado.\n"
        elif e.response.status_code == 404:
            message = f"  Error: Recurso '{resource}' no encontrado en VirusTotal.\n"
        else:
            message = f"  Error HTTP al contactar VirusTotal: {e.response.status_code} {e.response.reason}.\n"
        print(message.strip())
        report_file_handle.write(message + "\n")
        console_summary_message += message # Append to console summary
    except requests.exceptions.RequestException as e: # General network errors
        message = f"  Error de red al contactar VirusTotal: {type(e).__name__}.\n"
        print(message.strip())
        report_file_handle.write(message + "\n")
        console_summary_message += message # Append to console summary
    except json.JSONDecodeError as e_json:
        message = f"  Error al decodificar JSON de VirusTotal: {e_json}.\n"
        print(message.strip())
        report_file_handle.write(message + "\n")
        console_summary_message += message # Append to console summary
    except Exception as e: # Catch-all for other unexpected errors
        message = f"  Error inesperado durante la consulta a VirusTotal: {type(e).__name__} - {e}.\n"
        print(message.strip())
        report_file_handle.write(message + "\n")
        console_summary_message += message # Append to console summary
    finally:
        report_file_handle.write("--- Fin de Resultados de VirusTotal ---\n\n")
        print("--- Fin de Resultados de VirusTotal ---")

    # Ensure a default message if everything failed before console_summary_message was properly built
    if console_summary_message == f"  Resumen de VirusTotal para '{resource}':\n": # only the initial part
        console_summary_message += "  No se pudo generar el resumen detallado debido a un error.\n"

    return console_summary_message.strip() # Return the full summary for display_scan_findings

def get_viewdns_info(target, api_key, report_file_handle):
    print(f"\n--- Obteniendo información de ViewDNS para '{target}' ---")
    report_file_handle.write(f"--- Resultados de ViewDNS para '{target}' ---\n")
    summary_parts = []

    if not api_key:
        message = "  API key de ViewDNS no proporcionada. Omitiendo esta comprobación.\n"
        print(message.strip())
        report_file_handle.write(message)
        summary_parts.append(message)
        report_file_handle.write("--- Fin de Resultados de ViewDNS ---\n\n")
        return "\n\n".join(summary_parts)

    base_url = "https://api.viewdns.info"
    endpoints_to_query = []

    # Endpoint 1: WHOIS (for both IP and domain)
    endpoints_to_query.append({
        "name": "WHOIS",
        "url": f"{base_url}/whois/?domain={target}&apikey={api_key}&output=json"
    })

    # Endpoint 2: Reverse IP
    endpoints_to_query.append({
        "name": "Reverse IP",
        "url": f"{base_url}/reverseip/?host={target}&apikey={api_key}&output=json"
    })

    for endpoint_info in endpoints_to_query:
        endpoint_name = endpoint_info["name"]
        url = endpoint_info["url"]

        current_summary = f"--- Resultados de {endpoint_name} (ViewDNS) para '{target}' ---\n"
        report_file_handle.write(current_summary)
        print(f"  Consultando {endpoint_name} de ViewDNS para '{target}'...")

        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            data = response.json()

            if 'response' in data and isinstance(data['response'], dict) and data['response'].get('error'):
                error_msg_viewdns = data['response']['error']
                message = f"  Error de API de ViewDNS ({endpoint_name}): {error_msg_viewdns}\n"
                current_summary += message
                print(message.strip())
            else:
                if endpoint_name == "WHOIS":
                    whois_data = data.get('response', {}).get('whois', {})
                    if whois_data:
                        parsed_records = whois_data.get('parsed')
                        if parsed_records and isinstance(parsed_records, list) and any(rec.get('value') for rec in parsed_records):
                            current_summary += "  Datos WHOIS (Analizados):\n"
                            for record in parsed_records:
                                if record.get('name') and record.get('value'):
                                    current_summary += f"    {record['name']}: {record['value']}\n"
                        elif whois_data.get('raw'):
                            current_summary += "  Datos WHOIS (Crudos):\n"
                            current_summary += whois_data['raw'] + "\n"
                        else:
                            current_summary += "  No se encontraron datos WHOIS o estaban en un formato inesperado.\n"
                        print(f"    Datos de WHOIS para '{target}' obtenidos.")
                    else:
                        current_summary += "  No se encontraron datos WHOIS en la respuesta.\n"
                        print(f"    No se encontraron datos de WHOIS para '{target}'.")

                elif endpoint_name == "Reverse IP":
                    reverse_ip_data = data.get('response', {})
                    if reverse_ip_data:
                        domains = reverse_ip_data.get('domains', [])
                        current_summary += "  Dominios encontrados:\n"
                        for domain_entry in domains: # Ensure iteration over actual domain entries if it's a list of dicts
                            # Assuming 'domains' is a list of dicts like [{'name': 'domain1.com'}, {'name': 'domain2.com'}]
                            # Or if it's a list of strings: ['domain1.com', 'domain2.com']
                            if isinstance(domain_entry, dict) and 'name' in domain_entry:
                                current_summary += f"    - {domain_entry['name']}\n"
                            elif isinstance(domain_entry, str): # If it's just a list of strings
                                current_summary += f"    - {domain_entry}\n"
                        if not domains:
                             current_summary += "    No se encontraron dominios en la IP inversa.\n"
                        print(f"    Resultados de IP inversa para '{target}' obtenidos.")
                    else:
                        current_summary += "  No se encontraron datos de IP inversa en la respuesta.\n"
                        print(f"    No se encontraron datos de IP inversa para '{target}'.")

        except requests.exceptions.HTTPError as e:
            message = f"  Error HTTP ({endpoint_name}) al contactar ViewDNS: {e.response.status_code} {e.response.reason}.\n"
            current_summary += message
            print(message.strip())
        except requests.exceptions.RequestException as e:
            message = f"  Error de red ({endpoint_name}) al contactar ViewDNS: {e}.\n"
            current_summary += message
            print(message.strip())
        except json.JSONDecodeError as e_json: # Specific catch for JSON decoding errors
            message = f"  Error al decodificar JSON ({endpoint_name}) de ViewDNS: {e_json}. Respuesta: {response.text[:200]}...\n"
            current_summary += message
            print(message.strip())
        except Exception as e: # Generic catch-all for other unexpected errors
            message = f"  Error inesperado ({endpoint_name}) durante la consulta a ViewDNS: {type(e).__name__} - {e}.\n"
            current_summary += message
            print(message.strip())
        finally:
            current_summary += f"--- Fin de Resultados de {endpoint_name} (ViewDNS) ---\n"
            # Write the current_summary for this endpoint to the main report file
            # The report_file_handle is passed to get_viewdns_info and should be used here
            report_file_handle.write(current_summary) # This was missing, should write this part to file
            # report_file_handle.write("\n\n") # Add spacing if needed, but current_summary has its own end tag.
            summary_parts.append(current_summary.strip()) # This is for the return value, not file writing
            print(f"  Fin de la consulta de {endpoint_name} de ViewDNS.")

    # Final summary for the entire ViewDNS part (written to file after all endpoints)
    # report_file_handle.write("--- Fin de Resultados de ViewDNS ---\n\n") # This is already handled by the loop's finally or should be
    # The return value is what's used by display_scan_findings
    return "\n\n".join(summary_parts)


def display_scan_findings(current_scan_results):
    print("\n--- Resumen de Hallazgos del Escaneo ---")
    print(f"Objetivo Original: {current_scan_results.get('original_target', 'No disponible')}")
    print(f"Es IP de entrada: {'Sí' if current_scan_results.get('is_ip_address_input') else 'No'}")
    if not current_scan_results.get('is_ip_address_input'):
        print(f"IP Resuelta: {current_scan_results.get('resolved_ip', 'No disponible')}")
    print(f"IP Escaneada: {current_scan_results.get('target_ip_for_scan', 'No disponible')}")
    # report_file_name is not part of current_scan_results structure from perform_full_scan
    # It's handled in the main block. So we should get it from the global scan_results if needed here,
    # or ensure it's passed if this function is meant to be fully independent.
    # For now, assuming it might be in current_scan_results or not critical for this display.
    # print(f"Nombre del Archivo de Reporte: {current_scan_results.get('report_file_name', 'No disponible')}")


    print("\n--- Detección de Cloudflare ---")
    cf_results = current_scan_results.get('cloudflare_results', {})
    print(f"¿Detrás de Cloudflare?: {'Sí' if cf_results.get('is_cloudflare') else 'No'}")
    if cf_results.get('is_cloudflare') and cf_results.get('evidence'):
        print("Evidencia:")
        for ev in cf_results.get('evidence', []):
            print(f"  - {ev}")
    elif not cf_results: # If cf_results itself is missing or empty
            print("Resultados de Cloudflare no disponibles o no se ejecutó la verificación.")

    print("\n--- Subdominios Descubiertos ---")
    subdomains = current_scan_results.get('all_discovered_subdomains', [])
    if subdomains: # Check if list is not empty
        for sub in subdomains:
            print(f"  - {sub}")
    else:
        print("No se encontraron subdominios o la búsqueda no aplicó (ej. escaneo de IP directa).")

    print("\n--- IPs de Origen Potenciales (No Cloudflare) ---")
    origin_ips = current_scan_results.get('consolidated_potential_origin_ips', [])
    if origin_ips: # Check if list is not empty
        for ip_origin in origin_ips:
            print(f"  - {ip_origin}")
    else:
        print("No se encontraron IPs de origen potenciales, el objetivo no está detrás de Cloudflare, o la búsqueda no aplicó.")

    print("\n--- Puertos Abiertos en el Objetivo Principal ---")
    open_ports = current_scan_results.get('open_ports', [])
    if open_ports: # Check if list is not empty
        for port in open_ports:
            print(f"  - {port}/tcp")
    else:
        print("No se encontraron puertos abiertos o el escaneo de puertos falló/no se ejecutó.")

    print("\n--- Resumen de VirusTotal ---")
    # The get_virustotal_report function now returns a string which is the summary.
    vt_summary = current_scan_results.get('virustotal_summary', "Resumen de VirusTotal no disponible.")
    # Ensure vt_summary is a string before calling strip()
    if isinstance(vt_summary, str) and vt_summary.strip():
        print(vt_summary)
    else:
        print("Resumen de VirusTotal no disponible o no se ejecutó.")


    print("\n--- Resumen de ViewDNS ---")
    vd_summary = current_scan_results.get('viewdns_summary', "Resumen de ViewDNS no disponible.")
    if isinstance(vd_summary, str) and vd_summary.strip():
        print(vd_summary)
    else:
        print("Resumen de ViewDNS no disponible o no se ejecutó.")

    print("------------------------------------")

def scan_ports(ip):
    print(f"Escaneando puertos de {ip} con nmap directamente desde subprocess...")

    if shutil.which('nmap') is None:
        print("Error: nmap is not installed or not in PATH. Please install nmap to use port scanning.")
        return []

    try:
        # Comando nmap con escaneo SYN (-sS), T4 timing, sin ping (-Pn), para todos los puertos (--open para mostrar solo abiertos)
        # Consider adding -v for verbosity if needed for debugging, but it adds noise.
        # Ensure --open is used to only get open ports, simplifying parsing.
        # Using -p- for all 65535 ports. This can be slow.
        # For faster scans, one might specify common ports e.g., -p 1-1024,4444,8080 or use --top-ports 1000
        # Current command: nmap -sS -T4 -Pn -p- --open <IP>
        result = subprocess.check_output(
            ['nmap', '-sS', '-T4', '-Pn', '-p-', '--open', ip],
            universal_newlines=True,
            stderr=subprocess.PIPE # Capture stderr for better error reporting
        )

        open_ports = []
        for line in result.splitlines():
            # Example Nmap output line for an open port: "80/tcp open  http"
            if "/tcp" in line and "open" in line:
                try:
                    port_str = line.split('/')[0]
                    if port_str.isdigit(): # Ensure it's a number before converting
                        port = int(port_str)
                        print(f"Puerto {port}/tcp abierto")
                        open_ports.append(port)
                except (IndexError, ValueError) as e:
                    print(f"  Advertencia: No se pudo analizar la línea de puerto de nmap: '{line}'. Error: {e}")
                    continue # Skip to next line

        if not open_ports:
            print(f"No se encontraron puertos TCP abiertos para {ip} o nmap no los reportó en el formato esperado.")

        return open_ports

    except FileNotFoundError: # Specific error for nmap not being installed/found
        print("Error: Comando nmap no encontrado. Por favor, asegúrese de que nmap esté instalado y en el PATH del sistema.")
        return []
    except subprocess.CalledProcessError as e:
        # This error means nmap ran but returned a non-zero exit code.
        # e.output might contain partial results or info, e.g. if host is down and -Pn was used.
        # e.stderr often contains the actual error message from nmap.
        error_message = f"Error durante el escaneo de nmap para {ip}. Código de salida: {e.returncode}."
        if e.stdout: # Nmap might print to stdout even on error
            error_message += f" Salida de Nmap (stdout): {e.stdout.strip()}"
        if e.stderr: # Nmap often prints errors to stderr
            error_message += f" Salida de Nmap (stderr): {e.stderr.strip()}"
        print(error_message)
        return []
    except Exception as e: # Catch any other unexpected exceptions
        print(f"Error inesperado durante el escaneo de puertos para {ip}: {type(e).__name__} - {e}")
        return []


def check_reachability_with_ping(target_ip, report_file_handle):
    print(f"Intentando hacer ping a {target_ip}...")
    report_file_handle.write(f"--- Resultados del Ping a {target_ip} ---\n")
    try:
        # Ping with 1 packet (-c 1 for Linux/macOS, -n 1 for Windows)
        # Timeout for reply: -W 2 (Linux/macOS), -w 2000 (Windows, in ms)
        # Platform specific ping command
        if sys.platform.startswith('win'):
            command = ["ping", "-n", "1", "-w", "2000", target_ip]
        else: # Linux, macOS, etc.
            command = ["ping", "-c", "1", "-W", "2", target_ip]

        ping_output = subprocess.check_output(
            command,
            universal_newlines=True, # Decodes output to string
            timeout=5,  # Overall timeout for the subprocess call itself
            stderr=subprocess.PIPE # Capture stderr
        )

        # Try to find a canonical name if target_ip was an IP that resolved from a name
        # This is often present in the first line of ping output on some systems
        canonical_name_found = None
        first_line = ping_output.splitlines()[0] if ping_output.splitlines() else ""
        # Example: "PING google.com (142.250.195.174) 56(84) bytes of data."
        # Regex to capture the name if it's different from target_ip
        match = re.search(r"PING\s+([\w.-]+)\s+\(([^)]+)\)", first_line)
        if match:
            name_in_ping = match.group(1)
            ip_in_ping = match.group(2)
            if ip_in_ping == target_ip and name_in_ping != target_ip:
                canonical_name_found = name_in_ping

        if canonical_name_found:
            message = f"Ping a {target_ip} (nombre canónico/DNS: {canonical_name_found}) exitoso.\n"
            print(f"Ping a {target_ip} (nombre canónico/DNS: {canonical_name_found}) exitoso.")
        else:
            message = f"Ping a {target_ip} exitoso.\n"
            print(f"Ping a {target_ip} exitoso.")

        report_file_handle.write(message)
        report_file_handle.write("Salida completa del ping:\n" + ping_output + "\n")

    except subprocess.CalledProcessError as e:
        # Ping command ran but returned a non-zero exit code (e.g., host unreachable)
        message = f"No se pudo hacer ping a {target_ip} (Respuesta no exitosa o error de comando).\n"
        if e.stdout: # Sometimes output is on stdout even for errors
            message += f"Salida de Ping (stdout): {e.stdout.strip()}\n"
        if e.stderr: # Error messages often go to stderr
            message += f"Salida de Ping (stderr): {e.stderr.strip()}\n"
        print(f"No se pudo hacer ping a {target_ip}.")
        report_file_handle.write(message)
    except FileNotFoundError: # Ping command itself not found
        message = f"Comando 'ping' no encontrado. No se pudo verificar la alcanzabilidad para {target_ip}. Asegúrese de que 'ping' esté en el PATH del sistema.\n"
        print("Error: Comando 'ping' no encontrado.")
        report_file_handle.write(message)
    except subprocess.TimeoutExpired: # Overall subprocess call timed out
        message = f"Ping a {target_ip} timed out (límite de tiempo del subproceso excedido).\n"
        print(f"Ping a {target_ip} timed out.")
        report_file_handle.write(message)
    except Exception as e: # Catch any other unexpected exceptions
        message = f"Error inesperado durante el ping a {target_ip}: {type(e).__name__} - {e}.\n"
        print(f"Error inesperado durante el ping: {e}")
        report_file_handle.write(message)
    finally:
        report_file_handle.write("--- Fin de Resultados del Ping ---\n\n")


def get_dns_records(dominio):
    try:
        print(f"Realizando consulta DNS para {dominio}...")
        # socket.gethostbyname only returns one IP address for an A record.
        # For more comprehensive DNS info (like multiple A records, MX, NS, etc.),
        # dnspython should be used more extensively if needed elsewhere.
        # Here, it's used for a basic A record lookup.
        ip_address = socket.gethostbyname(dominio)
        print(f"Dirección IP para {dominio}: {ip_address}")
        return ip_address
    except socket.gaierror as e: # Specific error for DNS resolution failures
        print(f"No se pudo resolver el DNS para '{dominio}'. Error: {e}. "
              "Verifique que el nombre de dominio sea correcto y que tenga conexión a internet.")
        return None
    except Exception as e: # Catch any other unexpected errors
        print(f"Error inesperado durante la resolución DNS para '{dominio}': {type(e).__name__} - {e}")
        return None


def fetch_http_content(target_ip_for_request, port, path_segment, report_file_handle):
    # Ensure path_segment starts with a slash if it's not empty
    if not path_segment.startswith('/') and path_segment:
        path_segment = '/' + path_segment
    elif not path_segment: # Handle empty path_segment, default to '/'
        path_segment = '/'

    # Determine scheme based on common ports, default to http
    scheme = 'https' if port == 443 else 'http'
    url = f'{scheme}://{target_ip_for_request}:{port}{path_segment}'

    # Sanitize the target_ip_for_request and path_segment for filename creation
    safe_ip_filename_part = re.sub(r'[^\w.-]', '_', target_ip_for_request)
    # Remove leading slash for filename part if path_segment was '/'
    safe_path_filename_part = re.sub(r'[^\w.-]', '_', path_segment.strip('/'))
    if not safe_path_filename_part: # Default for root path
        safe_path_filename_part = 'index'

    # Construct filename to include IP, port, and path to avoid overwrites from different targets
    # Example: http_content_192_168_1_1_port_80_path_index.txt
    # Example: http_content_example_com_port_443_path_robots_txt.txt
    filename = f"http_content_{safe_ip_filename_part}_port_{port}_path_{safe_path_filename_part}.html" # Changed to .html

    try:
        print(f"Haciendo petición HTTP(S) a {url}...")
        # Standard User-Agent, allow redirects, short timeout, disable SSL verification for direct IP/untrusted certs
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False, headers={'User-Agent': 'Python Security Scanner/1.0'})

        # Write to file, now using .html extension for better rendering of HTML content
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"<!-- URL Solicitada: {url} -->\n")
            f.write(f"<!-- Código de Estado: {response.status_code} -->\n")
            f.write("<!-- Encabezados de Respuesta:\n")
            for key, value in response.headers.items():
                f.write(f"  {key}: {value}\n")
            f.write("-->\n\n") # End of headers comment
            f.write(response.text) # Write the actual content (could be HTML)

        success_message = f"Petición a {url} realizada (código {response.status_code}). Contenido guardado en {filename}."
        print(success_message)
        report_file_handle.write(success_message + "\n")
        return url # Return the actual URL fetched

    except requests.exceptions.SSLError as e_ssl:
        error_message = f"Error de SSL/TLS durante la petición a {url} (quizás necesita http:// en lugar de https:// o viceversa?): {e_ssl}"
        # If it was HTTPS and failed, could try HTTP as a fallback if appropriate, but not implemented here.
    except requests.exceptions.ConnectionError as e_conn:
        error_message = f"Error de conexión durante la petición a {url} (el puerto podría no estar abierto o el servidor no responde): {e_conn}"
    except requests.exceptions.Timeout as e_timeout:
        error_message = f"Timeout durante la petición a {url}: {e_timeout}"
    except requests.RequestException as e: # Catch other general request exceptions
        error_message = f"Error durante la petición HTTP(S) a {url}: {type(e).__name__} - {e}"
    except IOError as e_io: # Catch file writing errors
        error_message = f"Error de E/S al intentar escribir el contenido de {url} en '{filename}': {e_io}"
        # Still attempt to log to main report file if this happens
    except Exception as e_gen: # Catch any other unexpected errors
        error_message = f"Error inesperado al obtener contenido de {url}: {type(e_gen).__name__} - {e_gen}"

    # This block will be reached if any exception occurred
    print(error_message)
    if 'report_file_handle' in locals() and report_file_handle and not report_file_handle.closed:
        try:
            report_file_handle.write(error_message + "\n")
        except Exception as e_report_write:
            print(f"Error adicional: No se pudo escribir el mensaje de error en el archivo de reporte: {e_report_write}")
    return None # Return None as the fetch was not successful


def display_interactive_menu():
    print("\n--- Menú Interactivo ---")
    print("1. Listar todos los hallazgos del último escaneo") # Clarified
    print("2. Seleccionar IP para acciones (funcionalidad futura)") # Placeholder
    print("3. Obtener reporte de VirusTotal (para un nuevo recurso)")
    print("4. Obtener información de ViewDNS (para un nuevo recurso)")
    print("5. Escanear nuevo objetivo (actualiza los hallazgos principales)")
    print("6. Salir")

# Main execution block
if __name__ == '__main__':
    # scan_results will store results from the LATEST perform_full_scan call
    # This dictionary is updated when a new scan (initial or via menu option 5) is performed.
    scan_results = {}

    # --- Initial Target Input ---
    ip_input = input("Ingrese la dirección IP o el dominio que desea escanear: ").strip()
    if not ip_input:
        print("Error: El input no puede estar vacío. Por favor, ingrese una IP o dominio válido.")
        sys.exit(1)

    # --- API Key Configuration ---
    # SecurityTrails
    securitytrails_api_key_default = "z3mBcRxgWzQV_Wn0CPEKPGbMeX-Zh-RK" # User provided default
    securitytrails_api_key = input(f"Enter SecurityTrails API key (Enter for default: '{securitytrails_api_key_default[:10]}...'): ").strip() or securitytrails_api_key_default
    print(f"Using {'provided' if securitytrails_api_key != securitytrails_api_key_default else 'default'} SecurityTrails API key.")

    # VirusTotal
    virustotal_api_key_default = "8776df93922123e67cd4c288cc98af0541824aa956fa135b4cda4471b047700a" # User provided default
    virustotal_api_key = input(f"Enter VirusTotal API key (Enter for default: '{virustotal_api_key_default[:10]}...'): ").strip() or virustotal_api_key_default
    print(f"Using {'provided' if virustotal_api_key != virustotal_api_key_default else 'default'} VirusTotal API key.")

    # ViewDNS
    viewdns_api_key_default = "090cd963f55f4c55f5c229466aaca871b3809de1" # User provided default
    viewdns_api_key = input(f"Enter ViewDNS API key (Enter for default: '{viewdns_api_key_default[:10]}...'): ").strip() or viewdns_api_key_default
    print(f"Using {'provided' if viewdns_api_key != viewdns_api_key_default else 'default'} ViewDNS API key.")
    # --- End API Key Configuration ---

    # --- Main Report File Setup ---
    # Sanitize the initial input for a safe base filename
    safe_report_name_base = re.sub(r'[^\w.-]', '_', ip_input)
    if not safe_report_name_base: safe_report_name_base = "generic_scan" # Fallback if input is all special chars
    main_report_file_name = f"report_{safe_report_name_base}.txt"
    print(f"El informe principal se guardará en: {main_report_file_name}")
    # scan_results['report_file_name'] = main_report_file_name # Store globally for interactive mode if needed

    # --- Perform Initial Scan ---
    try:
        # Open the main report file in 'w' mode for the first scan (overwrite if exists)
        # Subsequent interactive actions will append ('a' mode)
        with open(main_report_file_name, 'w', encoding='utf-8') as f_reporte_principal:
            f_reporte_principal.write(f"--- Inicio del Reporte de Escaneo para: {ip_input} ---\n")
            f_reporte_principal.write(f"Clave SecurityTrails Usada: {'Sí' if securitytrails_api_key else 'No'}\n")
            f_reporte_principal.write(f"Clave VirusTotal Usada: {'Sí' if virustotal_api_key else 'No'}\n")
            f_reporte_principal.write(f"Clave ViewDNS Usada: {'Sí' if viewdns_api_key else 'No'}\n")
            f_reporte_principal.write("=======================================================\n\n")

            initial_scan_data = perform_full_scan(ip_input, f_reporte_principal,
                                                  securitytrails_api_key, virustotal_api_key, viewdns_api_key)
            if initial_scan_data:
                scan_results.update(initial_scan_data) # Populate global scan_results with the latest scan
                # Ensure original_target is correctly set from the input for this scan session
                scan_results['original_target'] = ip_input # perform_full_scan also sets this, but good to be sure
                print(f"Escaneo inicial para '{ip_input}' completado. Resultados guardados en {main_report_file_name}")
            else:
                # This case implies perform_full_scan returned None or an empty dict,
                # meaning a very early or critical failure.
                scan_results['original_target'] = ip_input # Still set original target
                scan_results['error_message'] = f"El escaneo inicial para {ip_input} falló o no devolvió datos."
                print(scan_results['error_message'])
                f_reporte_principal.write(f"ERROR CRÍTICO: {scan_results['error_message']}\n")

            f_reporte_principal.write(f"\n--- Fin del Reporte de Escaneo para: {ip_input} ---\n")

    except IOError as e:
        print(f"Error crítico de E/S al manejar el archivo de reporte principal {main_report_file_name}: {e}")
        print("No se pudieron guardar los resultados del reporte principal.")
        # Initialize essential scan_results keys if file operations failed early
        if 'original_target' not in scan_results: scan_results['original_target'] = ip_input
        # scan_results['report_file_name'] might not be useful if file couldn't be opened
        sys.exit(1) # Exit if the main report file cannot be handled

    # --- Interactive Mode ---
    print("\n--- Iniciando Modo Interactivo ---")
    while True:
        display_interactive_menu()
        choice = input("Seleccione una opción (1-6): ").strip()

        if choice == '1':
            if scan_results: # Check if there are any results to display
                display_scan_findings(scan_results) # Display findings from the latest scan
            else:
                print("No hay hallazgos de escaneo para mostrar. Realice un escaneo primero.")
        elif choice == '2':
            print("\nDEBUG: Opción 2 (Seleccionar IP para acciones) aún no implementada.")
            # Future: Implement select_ip_for_actions(scan_results, main_report_file_name, ...)
        elif choice == '3': # Get VirusTotal report for a new, specific resource
            print("\n--- Obtener Reporte de VirusTotal (Interactivo) ---")
            resource_vt = input("Ingrese la IP o Dominio para consultar en VirusTotal: ").strip()
            if not resource_vt:
                print("Entrada vacía. No se consultará VirusTotal.")
            elif not virustotal_api_key:
                print("Advertencia: La clave API de VirusTotal no está disponible. No se puede consultar.")
            else:
                try:
                    with open(main_report_file_name, 'a', encoding='utf-8') as f_reporte_interactive:
                        f_reporte_interactive.write(f"\n--- Reporte VirusTotal Interactivo para '{resource_vt}' (Sesión Interactiva) ---\n")
                        # This call to get_virustotal_report will print to console AND write to file.
                        # The returned summary is not explicitly used here, but could be if needed.
                        vt_interactive_summary = get_virustotal_report(resource_vt, virustotal_api_key, f_reporte_interactive)
                        # We can print the summary obtained to the console as well for immediate feedback
                        print("\n--- Resumen de VirusTotal para Recurso Interactivo ---")
                        print(vt_interactive_summary if vt_interactive_summary.strip() else "No se generó resumen o hubo un error.")
                        print(f"Consulta a VirusTotal para '{resource_vt}' completada. Detalles añadidos a {main_report_file_name}.")
                except IOError as e:
                    print(f"Error al escribir en el archivo de reporte ({main_report_file_name}): {e}")
        elif choice == '4': # Get ViewDNS info for a new, specific resource
            print("\n--- Obtener Información de ViewDNS (Interactivo) ---")
            resource_vd = input("Ingrese la IP o Dominio para consultar en ViewDNS: ").strip()
            if not resource_vd:
                print("Entrada vacía. No se consultará ViewDNS.")
            elif not viewdns_api_key:
                print("Advertencia: La clave API de ViewDNS no está disponible. No se puede consultar.")
            else:
                try:
                    with open(main_report_file_name, 'a', encoding='utf-8') as f_reporte_interactive:
                        f_reporte_interactive.write(f"\n--- Información ViewDNS Interactiva para '{resource_vd}' (Sesión Interactiva) ---\n")
                        # get_viewdns_info writes to file and returns a summary string.
                        vd_interactive_summary = get_viewdns_info(resource_vd, viewdns_api_key, f_reporte_interactive)
                        print("\n--- Resumen de ViewDNS para Recurso Interactivo ---")
                        print(vd_interactive_summary if vd_interactive_summary.strip() else "No se generó resumen o hubo un error.")
                        print(f"Consulta a ViewDNS para '{resource_vd}' completada. Detalles añadidos a {main_report_file_name}.")
                except IOError as e:
                    print(f"Error al escribir en el archivo de reporte ({main_report_file_name}): {e}")
        elif choice == '5': # Scan a new target
            print("\n--- Escanear Nuevo Objetivo ---")
            new_target_input = input("Ingrese la nueva IP o Dominio a escanear: ").strip()
            if not new_target_input:
                print("Entrada vacía. No se escaneará un nuevo objetivo.")
            else:
                ip_input = new_target_input # Update the main target reference
                print(f"Iniciando nuevo escaneo para '{ip_input}'. Los resultados se añadirán a {main_report_file_name}")
                try:
                    with open(main_report_file_name, 'a', encoding='utf-8') as f_reporte_interactive:
                        f_reporte_interactive.write(f"\n\n=== INICIO DE NUEVO ESCANEO INTERACTIVO PARA: {ip_input} ===\n")
                        f_reporte_interactive.write(f"Clave SecurityTrails Usada: {'Sí' if securitytrails_api_key else 'No'}\n")
                        f_reporte_interactive.write(f"Clave VirusTotal Usada: {'Sí' if virustotal_api_key else 'No'}\n")
                        f_reporte_interactive.write(f"Clave ViewDNS Usada: {'Sí' if viewdns_api_key else 'No'}\n")
                        f_reporte_interactive.write("=======================================================\n\n")

                        # Perform the new full scan
                        new_scan_data = perform_full_scan(ip_input, f_reporte_interactive,
                                                          securitytrails_api_key, virustotal_api_key, viewdns_api_key)
                        if new_scan_data:
                            scan_results.clear() # Clear previous scan results
                            scan_results.update(new_scan_data) # Update global scan_results with the new scan
                            scan_results['original_target'] = ip_input # Ensure original_target is updated
                            print(f"Nuevo escaneo para '{ip_input}' completado. 'Listar todos los hallazgos' ahora mostrará estos resultados.")
                        else:
                            # Handle critical failure of the new scan
                            error_msg_new_scan = f"El nuevo escaneo para '{ip_input}' falló o no devolvió datos."
                            scan_results['original_target'] = ip_input # Update target even if scan failed
                            scan_results['error_message'] = error_msg_new_scan
                            print(error_msg_new_scan)
                            f_reporte_interactive.write(f"ERROR CRÍTICO (nuevo escaneo): {error_msg_new_scan}\n")

                        f_reporte_interactive.write(f"\n=== FIN DE NUEVO ESCANEO INTERACTIVO PARA: {ip_input} ===\n")
                except IOError as e:
                    print(f"Error al abrir o escribir en el archivo de reporte {main_report_file_name}: {e}")
        elif choice == '6':
            print("\nSaliendo del modo interactivo...")
            break
        else:
            print("\nOpción no válida. Por favor, intente de nuevo.")

        if choice != '6': # Don't ask for "Enter to continue" if exiting
            try:
                input("\nPresione Enter para continuar...")
            except EOFError: # Handle EOF if input stream is closed (e.g. piping input)
                print("\nEOF detectado, saliendo...")
                break


    print("Script terminado.")
