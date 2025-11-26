import socket
import requests
import whois
import dns.resolver
import dns.zone
import dns.query
import ssl
import sys
import platform
import subprocess
import time
import os
import re
import random
from datetime import datetime

# Arayüz Kütüphaneleri
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

class UltimateScanner:
    def __init__(self, target):
        self.target = target
        # URL ve Hostname Ayrıştırma
        if self.target.startswith("http://"):
            self.hostname = self.target.replace("http://", "").split("/")[0]
            self.protocol = "http"
            self.base_url = self.target
        elif self.target.startswith("https://"):
            self.hostname = self.target.replace("https://", "").split("/")[0]
            self.protocol = "https"
            self.base_url = self.target
        else:
            self.hostname = self.target
            self.protocol = "https"
            self.base_url = f"https://{self.target}"
        
        try:
            self.ip_address = socket.gethostbyname(self.hostname)
        except:
            self.ip_address = None
            
        self.report_data = {
            "target": self.hostname,
            "ip": self.ip_address,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "modules": []
        }
        
        # Tarama sırasında bloklanmamak için User-Agent listesi
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        self.headers = {'User-Agent': random.choice(self.user_agents)}

    def add_to_report(self, title, content, severity="info"):
        """Rapor verisine ekleme yapar"""
        self.report_data["modules"].append({
            "title": title,
            "content": content,
            "severity": severity
        })

    # --- 1. WHOIS LOOKUP ---
    def mod_whois(self):
        try:
            w = whois.whois(self.hostname)
            info = f"Registrar: {w.registrar}\nOrg: {w.org}\nCreation Date: {w.creation_date}"
            console.print(Panel(info, title="[bold green]1. WHOIS BİLGİSİ[/bold green]", border_style="green"))
            self.add_to_report("Whois", info.replace("\n", "<br>"), "info")
        except Exception as e:
            console.print("[dim]Whois bilgisi alınamadı.[/dim]")

    # --- 2. DNS & CLOUDFLARE ---
    def mod_dns(self):
        content = ""
        # DNS Kayıtları
        for record in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(self.hostname, record)
                for rdata in answers:
                    content += f"[{record}] {str(rdata)[:50]}\n"
            except: pass
            
        # Cloudflare Kontrolü
        cf_detected = False
        try:
            r = requests.head(self.base_url, timeout=5)
            if "CF-RAY" in r.headers or "cloudflare" in r.headers.get("Server", "").lower():
                content += "\n[!] Cloudflare Tespit Edildi (Gerçek IP Gizli)"
                cf_detected = True
        except: pass
        
        console.print(Panel(content.strip(), title="[bold blue]2. DNS & CLOUDFLARE[/bold blue]", border_style="blue"))
        self.add_to_report("DNS Bilgileri", content.replace("\n", "<br>"), "warning" if cf_detected else "info")

    # --- 3. ZONE TRANSFER (AXFR) ---
    def mod_zone_transfer(self):
        log = "Zone Transfer Başarısız (Güvenli Yapılandırma)"
        severity = "success"
        try:
            ns_answers = dns.resolver.resolve(self.hostname, 'NS')
            for ns in ns_answers:
                try:
                    ns_ip = socket.gethostbyname(str(ns))
                    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.hostname, timeout=2))
                    log = f"[!] KRİTİK: {ns} Sunucusu Zone Transfer'e İzin Veriyor!\n"
                    for n, _ in z.nodes.items():
                        log += f"- {n}\n"
                    severity = "danger"
                    break 
                except: continue
        except: pass
        
        color = "red" if severity == "danger" else "green"
        console.print(Panel(log[:200] + ("..." if len(log)>200 else ""), title="[bold yellow]3. ZONE TRANSFER[/bold yellow]", border_style=color))
        self.add_to_report("Zone Transfer", log.replace("\n", "<br>"), severity)

    # --- 4. PORT SCAN (Hızlı) ---
    def mod_port_scan(self):
        if not self.ip_address: return
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
        open_ports = []
        
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((self.ip_address, port)) == 0:
                open_ports.append(str(port))
            s.close()
            
        msg = ", ".join(open_ports) if open_ports else "Yaygın portlar kapalı."
        console.print(Panel(f"Açık Portlar: {msg}", title="[bold magenta]4. PORT TARAMASI[/bold magenta]", border_style="magenta"))
        self.add_to_report("Port Taraması", msg, "warning" if open_ports else "info")

    # --- 5. HTTP HEADERS & WAF ---
    def mod_headers_waf(self):
        try:
            r = requests.head(self.base_url, timeout=5, headers=self.headers)
            h = r.headers
            
            # Header Analizi
            headers_info = ""
            for k in ['Server', 'X-Powered-By', 'Strict-Transport-Security']:
                if k in h: headers_info += f"{k}: {h[k]}\n"
            
            # WAF Tespiti
            waf_msg = "WAF Tespit Edilemedi"
            if 'x-amz-cf-id' in h: waf_msg = "WAF: AWS CloudFront"
            elif 'cf-ray' in h: waf_msg = "WAF: Cloudflare"
            elif 'X-Iinfo' in h: waf_msg = "WAF: Incapsula"
            
            content = f"{headers_info}\n{waf_msg}"
            console.print(Panel(content.strip(), title="[bold cyan]5. HTTP BAŞLIKLARI & WAF[/bold cyan]", border_style="cyan"))
            self.add_to_report("Headers & WAF", content.replace("\n", "<br>"), "info")
        except: pass

    # --- 6. SSL ANALİZİ ---
    def mod_ssl(self):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    exp_date = cert['notAfter']
                    issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                    msg = f"Yayınlayan: {issuer}\nBitiş Tarihi: {exp_date}"
                    console.print(Panel(msg, title="[bold green]6. SSL SERTİFİKASI[/bold green]", border_style="green"))
                    self.add_to_report("SSL", msg.replace("\n", "<br>"), "success")
        except: pass

    # --- 7. ROBOTS.TXT & SITEMAP ---
    def mod_files(self):
        files_found = []
        for f in ["robots.txt", "sitemap.xml", ".env", ".git/HEAD"]:
            try:
                r = requests.head(f"{self.base_url}/{f}", headers=self.headers, timeout=3)
                if r.status_code == 200:
                    files_found.append(f)
            except: pass
            
        msg = ", ".join(files_found) if files_found else "Kritik dosya bulunamadı."
        console.print(Panel(msg, title="[bold white]7. DOSYA TARAMASI[/bold white]", border_style="white"))
        self.add_to_report("Dosyalar", msg, "warning" if ".env" in files_found else "info")

    # --- 8. SUBDOMAIN TARAMA (crt.sh) ---
    def mod_subdomains(self):
        try:
            url = f"https://crt.sh/?q=%.{self.hostname}&output=json"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                subs = set(entry['name_value'] for entry in r.json())
                # İlk 10 tanesini göster
                show_subs = list(subs)[:10]
                msg = "\n".join(show_subs)
                if len(subs) > 10: msg += f"\n... ve {len(subs)-10} adet daha."
                
                console.print(Panel(msg, title="[bold yellow]8. SUBDOMAINS[/bold yellow]", border_style="yellow"))
                self.add_to_report("Subdomains", f"Toplam {len(subs)} adet bulundu.<br>" + "<br>".join(show_subs), "info")
        except: pass

    # --- 9. TRACEROUTE ---
    def mod_traceroute(self):
        cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
        param = '-h' if platform.system().lower() == 'windows' else '-m'
        try:
            # Sadece 5 hop
            out = subprocess.check_output([cmd, param, '5', self.hostname], encoding='cp857' if platform.system()=='Windows' else 'utf-8')
            console.print(Panel("Traceroute tamamlandı (Rapora eklendi).", title="[bold blue]9. TRACEROUTE[/bold blue]", border_style="blue"))
            self.add_to_report("Traceroute", out.replace("\n", "<br>"), "info")
        except: pass

    # --- 10. IP LOCATION ---
    def mod_location(self):
        if not self.ip_address: return
        try:
            d = requests.get(f"http://ip-api.com/json/{self.ip_address}").json()
            if d['status'] == 'success':
                loc = f"{d['country']}, {d['city']} ({d['isp']})"
                console.print(Panel(loc, title="[bold cyan]10. IP KONUMU[/bold cyan]", border_style="cyan"))
                self.add_to_report("Konum", loc, "info")
        except: pass

    # --- 11. LINK GRABBER ---
    def mod_links(self):
        try:
            r = requests.get(self.base_url, headers=self.headers, timeout=5)
            links = re.findall('href="(http[s]?://.*?)"', r.text)
            count = len(set(links))
            console.print(Panel(f"Sayfada {count} dış bağlantı bulundu.", title="[bold magenta]11. LINK GRABBER[/bold magenta]", border_style="magenta"))
            self.add_to_report("Linkler", f"Bulunan Dış Link Sayısı: {count}", "info")
        except: pass

    # --- 12. ADMIN PANEL FINDER (Aktif) ---
    def mod_admin_finder(self):
        paths = ["admin/", "login/", "wp-admin/", "panel/", "dashboard/", "yonetim/"]
        found = []
        for p in paths:
            try:
                r = requests.get(f"{self.base_url}/{p}", headers=self.headers, timeout=3)
                if r.status_code == 200:
                    found.append(p)
            except: pass
        
        msg = ", ".join(found) if found else "Standart admin yolları bulunamadı."
        color = "red" if found else "green"
        console.print(Panel(msg, title="[bold red]12. ADMIN PANEL TARAMASI[/bold red]", border_style=color))
        self.add_to_report("Admin Panelleri", msg, "danger" if found else "success")

    # --- 13. EMAIL HARVESTER (Aktif) ---
    def mod_emails(self):
        try:
            r = requests.get(self.base_url, headers=self.headers, timeout=5)
            emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", r.text, re.I))
            msg = "\n".join(emails) if emails else "E-posta bulunamadı."
            console.print(Panel(msg, title="[bold yellow]13. E-POSTA AVCISI[/bold yellow]", border_style="yellow"))
            self.add_to_report("E-Postalar", msg.replace("\n", "<br>"), "warning" if emails else "info")
        except: pass

    # --- 14. WORDPRESS USER ENUM (Aktif) ---
    def mod_wp_users(self):
        try:
            r = requests.get(f"{self.base_url}/wp-json/wp/v2/users", headers=self.headers, timeout=5)
            if r.status_code == 200:
                users = [u['slug'] for u in r.json()]
                msg = ", ".join(users)
                console.print(Panel(msg, title="[bold red]14. WP KULLANICILARI[/bold red]", border_style="red"))
                self.add_to_report("WP Kullanıcıları", msg, "danger")
            else:
                console.print(Panel("WP API Kapalı veya Site WP Değil.", title="14. WP USER ENUM", border_style="green"))
        except: pass

    # --- HTML RAPOR OLUŞTURMA ---
    def generate_html_report(self):
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Güvenlik Tarama Raporu - {self.hostname}</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background-color: #1e1e1e; color: #f0f0f0; margin: 0; padding: 20px; }}
                .container {{ max-width: 900px; margin: auto; }}
                h1 {{ border-bottom: 2px solid #00bcd4; padding-bottom: 10px; }}
                .meta {{ color: #888; font-size: 0.9em; margin-bottom: 20px; }}
                .card {{ background-color: #2d2d2d; margin-bottom: 15px; border-radius: 5px; overflow: hidden; }}
                .card-header {{ background-color: #383838; padding: 10px 15px; font-weight: bold; color: #fff; }}
                .card-body {{ padding: 15px; font-size: 0.95em; line-height: 1.5; }}
                .severity-danger {{ border-left: 5px solid #f44336; }}
                .severity-warning {{ border-left: 5px solid #ff9800; }}
                .severity-success {{ border-left: 5px solid #4caf50; }}
                .severity-info {{ border-left: 5px solid #2196f3; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Ultimate Security Scanner v8.0</h1>
                <div class="meta">
                    Hedef: {self.hostname} ({self.ip_address})<br>
                    Tarih: {self.report_data['start_time']}
                </div>
        """
        
        for item in self.report_data["modules"]:
            html += f"""
                <div class="card severity-{item['severity']}">
                    <div class="card-header">{item['title']}</div>
                    <div class="card-body">{item['content']}</div>
                </div>
            """
            
        html += "</div></body></html>"
        
        filename = f"SCAN_REPORT_{self.hostname.replace('.', '_')}.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        return filename

    # --- ANA ÇALIŞTIRMA FONKSİYONU ---
    def run(self):
        console.clear()
        console.print(Panel.fit(f"[bold white]ULTIMATE SECURITY SCANNER v8.0[/bold white]\n[dim]Hedef: {self.hostname}[/dim]", style="bold blue"))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
            transient=True
        ) as progress:
            
            task = progress.add_task("[cyan]Sistem Taranıyor...", total=14)
            
            # Adım Adım Çalıştırma
            steps = [
                (self.mod_whois, "Whois Bilgisi"),
                (self.mod_dns, "DNS & Cloudflare"),
                (self.mod_zone_transfer, "Zone Transfer"),
                (self.mod_port_scan, "Port Taraması"),
                (self.mod_headers_waf, "Headers & WAF"),
                (self.mod_ssl, "SSL Analizi"),
                (self.mod_files, "Dosya Taraması"),
                (self.mod_subdomains, "Subdomainler"),
                (self.mod_traceroute, "Traceroute"),
                (self.mod_location, "Konum"),
                (self.mod_links, "Link Grabber"),
                (self.mod_admin_finder, "Admin Panel Finder"),
                (self.mod_emails, "Email Harvester"),
                (self.mod_wp_users, "WP User Enum")
            ]
            
            for func, desc in steps:
                progress.update(task, description=f"[cyan]{desc} çalıştırılıyor...[/cyan]")
                func()
                progress.advance(task)
                time.sleep(0.5) # Arayüzün çok hızlı akmaması için kısa bekleme

        console.rule("[bold green]TARAMA TAMAMLANDI[/bold green]")
        report_file = self.generate_html_report()
        console.print(Panel(f"Detaylı Rapor Oluşturuldu:\n[underline bold]{os.path.abspath(report_file)}[/underline bold]", title="HTML RAPOR", border_style="gold1"))

if __name__ == "__main__":
    try:
        target_input = console.input("[bold yellow]Hedef Siteyi Giriniz (örn: google.com): [/bold yellow]")
        if target_input:
            scanner = UltimateScanner(target_input)
            scanner.run()
    except KeyboardInterrupt:
        console.print("\n[red]İşlem iptal edildi.[/red]")
