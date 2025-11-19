import subprocess
import platform
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
import time
import nmap # YENİ KÜTÜPHANE

MAX_PING_THREADS = 254 

def ping_host(ip_adresi):
    """
    Belirtilen IP adresine ping atar.
    """
    if platform.system() == "Windows":
        komut = ["ping", "-n", "1", "-w", "500", str(ip_adresi)]
    else:
        komut = ["ping", "-c", "1", "-W", "1", str(ip_adresi)]
        
    try:
        result = subprocess.run(komut, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
        if result.returncode == 0:
            if "TTL=" in result.stdout or "1 received" in result.stdout or "0% packet loss" in result.stdout:
                return (ip_adresi, True)
        return (ip_adresi, False)
        
    except (subprocess.TimeoutExpired, Exception):
        return (ip_adresi, False)

def run_port_scan(ip_adresi):
    """
    Aktif hostlar için detaylı Nmap port taraması yapar.
    """
    nm = nmap.PortScanner()
    
    # -F: Hızlı tarama (en popüler 1000 port)
    # -T4: Zamanlama (daha hızlı tarama)
    print(f"   [+] Detaylı tarama başlatılıyor: {ip_adresi}")
    
    try:
        nm.scan(ip_adresi, arguments='-F -T4')
        
        # Eğer tarama başarılıysa ve port bilgisi varsa
        if ip_adresi in nm.all_hosts():
            host_info = nm[ip_adresi]
            
            # TCP portlarını kontrol et
            if 'tcp' in host_info:
                açik_portlar = host_info['tcp']
                
                detay = {}
                for port, info in açik_portlar.items():
                    # Portun durumu 'open' ise bilgileri al
                    if info['state'] == 'open':
                        detay[port] = {
                            'servis': info.get('name', 'Bilinmiyor'),
                            'durum': info.get('state', 'kapalı')
                        }
                return detay
        
        return None # Açık port bulunamadı
        
    except nmap.PortScannerError as e:
        print(f"   [!] Nmap Hatası ({ip_adresi}): {e}")
        return None


def scan_network(network_range):
    """Ağı tarar, aktif hostları paralel bulur ve detaylı port taraması yapar."""
    
    start_time = time.time()
    
    try:
        ag = ipaddress.ip_network(network_range, strict=False)
        all_hosts = [str(host) for host in ag.hosts()]
    except ValueError:
        print(f"❌ Hata: Hatalı IP aralığı formatı girdin. Örnek: 192.168.1.0/24")
        sys.exit(1)
        
    hosts_to_scan = [ip for ip in all_hosts if ip != str(ag.network_address) and ip != str(ag.broadcast_address)]
    
    print(f"\n=======================================================")
    print(f"✅ DETAYLI NETWORK TARAYICI BAŞLATILIYOR...")
    print(f"📡 Hedeflenen Ağ: {network_range} ({len(hosts_to_scan)} olası host)")
    print(f"⚡ Ping Tarama Thread Sayısı: {MAX_PING_THREADS}")
    print(f"=======================================================")
    
    aktif_host_ips = []
    
    # Adım 1: Paralel Ping Taraması (Host Tespiti)
    print("\n--- 1. ADIM: HIZLI HOST TESPİTİ (PING) ---")
    with ThreadPoolExecutor(max_workers=MAX_PING_THREADS) as executor:
        results = executor.map(ping_host, hosts_to_scan)
        
        for ip, is_up in results:
            if is_up:
                aktif_host_ips.append(ip)
                print(f"🟢 {ip:<15} -> AKTİF")
                
    if not aktif_host_ips:
        print("🤷‍♂️ Ağda yanıt veren aktif host bulunamadı.")
        return
        
    # Adım 2: Detaylı Port Taraması (Aktif Hostlar Üzerinde)
    print("\n--- 2. ADIM: AKTİF HOSTLARDA DETAYLI PORT TARAMASI ---")
    
    # Nmap taramasını da hızlandırmak için yeni bir ThreadPool kullanabiliriz
    with ThreadPoolExecutor(max_workers=len(aktif_host_ips)) as executor:
        # run_port_scan fonksiyonunu aktif hostlar listesine paralel olarak uygula
        port_scan_results = executor.map(run_port_scan, aktif_host_ips)

    
    # Sonuçların Raporlanması
    print("\n==================== SONUÇ RAPORU =====================")
    for ip, port_detaylari in zip(aktif_host_ips, port_scan_results):
        print(f"✅ HOST: {ip}")
        if port_detaylari:
            for port, detay in port_detaylari.items():
                print(f"   > PORT {port:<5} | DURUM: {detay['durum'].upper():<7} | SERVİS: {detay['servis']}")
        else:
            print("   > Port taramasında açık servis bulunamadı.")
    
    elapsed_time = time.time() - start_time
    print("-------------------------------------------------------")
    print(f"⏰ TOPLAM SÜRE: {elapsed_time:.2f} saniye")
    print(f"✅ Tarama Yapılan Aktif Host Sayısı: {len(aktif_host_ips)}")
    print("=======================================================")


def main():
    """Aracın komut satırı argümanlarını yönetir."""
    parser = argparse.ArgumentParser(
        description="DETAYLI NETWORK TARAYICI: CIDR aralığındaki hostları bulur ve açık portlarını Nmap ile tespit eder.",
        epilog="Kullanım Örneği: python3 DetailedScanner.py 192.168.1.0/24"
    )
    
    parser.add_argument(
        "network_range",
        type=str,
        help="Taranacak Network aralığı (CIDR formatında, örn: 192.168.1.0/24)"
    )
    
    args = parser.parse_args()
    scan_network(args.network_range)


if __name__ == "__main__":
    main()