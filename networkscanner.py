import os
import sys
import nmap
import scapy.all as scapy
import requests
from concurrent.futures import ThreadPoolExecutor
def ascii_art():
    ascii_art =         """
                          _..._      .-'''-.                                     .-'''-.                           _..._                     
                       .-'_..._''.  '   _    \_______                           '   _    \                      .-'_..._''.            .---. 
                     .' .'      './   /` '.   \  ___ `'.        __.....__     /   /` '.   \              .--. .' .'      '..--.        |   | 
                    / .'         .   |     \  '' |--.\  \   .-''         '.  .   |     \  '  _.._    _.._|__|/ .'          |__|        |   | 
                   . '           |   '      |  | |    \  ' /     .-''"'-.  `.|   '      |  .' .._| .' .._.--. '            .--.        |   | 
                   | |           \    \     / /| |     |  /     /________\   \    \     / /| '     | '   |  | |            |  |   __   |   | 
.--------..--------| |            `.   ` ..' / | |     |  |                  |`.   ` ..' __| |__ __| |__ |  | |            |  |.:--.'. |   | 
|____    ||____    . '               '-...-'`  | |     ' .\    .-------------'   '-...-'|__   __|__   __||  . '            |  / |   \ ||   | 
    /   /     /   / \ '.          .            | |___.' /' \    '-.____...---.             | |     | |   |  |\ '.          |  `" __ | ||   | 
  .'   /    .'   /   '. `._____.-'/           /_______.'/   `.             .'              | |     | |   |__| '. `._____.-'|__|.'.''| ||   | 
 /    /___ /    /___   `-.______ /            \_______|/      `''-...... -'                | |     | |          `-.______ /   / /   | |'---' 
|         |         |           `                                                          | |     | |                   `    \ \._,\ '/     
|_________|_________|                                                                      |_|     |_|                         `--'  `"      
    """
    print(ascii_art)
def menu():
    ascii_art()
    print("""
    ============================================
    [1] Nmap Port Tarama
    [2] Network Sniffing (Scapy)
    [3] WordPress Zafiyet Tarama (Basitleştirilmiş)
    [4] Directory Brute Forcing
    [0] Çıkış
    ============================================
    """)

def nmap_scan():
    target = input("Hedef IP veya Domain: ")
    scanner = nmap.PortScanner()
    print(f"[*] {target} üzerinde tarama yapılıyor...")
    scanner.scan(target, arguments='-sV')  # Servis taraması
    for host in scanner.all_hosts():
        print(f"\n[+] Hedef: {host}")
        print("Açık Portlar:")
        for port, info in scanner[host]['tcp'].items():
            print(f"  Port: {port} | Durum: {info['state']} | Servis: {info['name']}")

def sniff_network():
    interface = input("Dinlenecek ağ arayüzü (örneğin: eth0, wlan0): ")
    print(f"[*] {interface} üzerinde paketler dinleniyor...")
    try:
        scapy.sniff(iface=interface, prn=lambda pkt: pkt.summary(), count=10)  # 10 paket dinle
    except KeyboardInterrupt:
        print("\n[!] Sniffing durduruldu.")

def wp_scan():
    target = input("Hedef WordPress site = ")
    vuln_paths = [
        "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/readme.html", 
        "/wp-content/debug.log", "/wp-config.php"
    ]
    print(f"[*] {target} üzerinde WordPress zafiyet taramasi baslatildi.")
    for path in vuln_paths:
        url = target + path
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Bulundu: {url}")
        else:
            print(f"[-] Bulunamadı: {url}")


def dir_brute_force():
    target = input("Hedef site (http://example.com): ")
    wordlist = input("Wordlist dosyasının yolu: ")
    threads = int(input("Thread sayısı (önerilen 5): "))

    if not os.path.isfile(wordlist):
        print("[!] Wordlist dosyası bulunamadı!")
        return
    
    print(f"[*] {target} üzerinde brute force başlatılıyor...")

    def check_path(path):
        url = f"{target}/{path.strip()}"
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Bulundu: {url}")
        else:
            print(f"[-] Denendi: {url}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        with open(wordlist, "r") as file:
            executor.map(check_path, file)


if __name__ == "__main__":
    while True:
        menu()
        choice = input("Seçiminiz: ")
        if choice == "1":
            nmap_scan()
        elif choice == "2":
            sniff_network()
        elif choice == "3":
            wp_scan()
        elif choice == "4":
            dir_brute_force()
        elif choice == "0":
            print("Çıkış yapılıyor...")
            sys.exit()
        else:
            print("[!] Geçersiz seçenek, tekrar deneyin.")
