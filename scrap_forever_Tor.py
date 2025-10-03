import requests
import re
import argparse
import concurrent.futures
import urllib3
import time
import socket
import socks
import json
import os
import pickle
import sqlite3
import threading
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import whois
import dns.resolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Requests.')
parser.add_argument('-t', dest='scrap_url', help='https://site.com.br', default=None)
parser.add_argument('-o', '--output', dest='scrap_out_path',
                    help='Salva data.', default=None)
parser.add_argument('-p', '--proxy', dest='scrap_proxy', help='-p http://127.0.0.1:8080', required=False)
parser.add_argument('-a', '--auth', dest='scrap_auth', help='-a Besic aqsdiqjewqd==', required=False)
parser.add_argument('-c', '--cookie', dest='scrap_cookie', help='-c PHPSESSION=cookie', required=False)
parser.add_argument('--user-agent', dest='scrap_user_agent', help='--user-agent Mozilla/5.0', required=False)
parser.add_argument('-n', '--threads', dest='num_threads', type=int, default=10,
                    help='Number of threads (default: 10)')
parser.add_argument('--tor', action='store_true', dest='use_tor',
                    help='Use Tor network via SOCKS proxy (default: socks5://127.0.0.1:9050)')
parser.add_argument('--tor-port', dest='tor_port', type=int, default=9050,
                    help='Tor SOCKS port (default: 9050)')
parser.add_argument('--max-urls', dest='max_urls', type=int, default=0,
                    help='Maximum number of URLs to process (0 = unlimited)')
parser.add_argument('--delay', dest='delay', type=float, default=1.0,
                    help='Delay between requests in seconds (default: 1.0)')
parser.add_argument('--deep-only', action='store_true', dest='deep_only',
                    help='Only process deep web URLs (.onion, .i2p, etc.)')
parser.add_argument('--checkpoint', dest='checkpoint_file', default='scrap_checkpoint.pkl',
                    help='Checkpoint file for restore (default: scrap_checkpoint.pkl)')
parser.add_argument('--restore', action='store_true', dest='restore', help='Restore from checkpoint file')
parser.add_argument('--no-checkpoint', action='store_true', dest='no_checkpoint',
                    help='Disable checkpoint saving')
parser.add_argument('--db', dest='db_file', default='scrap_data.db',
                    help='SQLite database file (default: scrap_data.db)')


def collect_parser_defaults(parser_obj):
    defaults = {}
    for action in parser_obj._actions:
        dest = getattr(action, 'dest', None)
        if not dest or dest == argparse.SUPPRESS:
            continue
        defaults[dest] = action.default
    return defaults


parser_defaults = collect_parser_defaults(parser)
args = parser.parse_args()

if not args.restore and (not args.scrap_url or len(args.scrap_url) <= 1 or not args.scrap_out_path):
    print(''' 
   python3 forever_scrap.py -h/--help

    -t Target to web scraping (Ex. -t https://site.com)
    -o output file (Ex. -o output.txt )
    -p/--proxy set proxy (Ex. -p http://127.0.0.1:8080)
    -a/--auth set auth (Ex. -a Authorization: aqsdiqjewqd==)
    -c/--cookie set cookie (Ex. -c PHPSESSION=cookie)
    -n/--threads Number of threads (default: 10)
    --tor Use Tor network via SOCKS proxy
    --tor-port Tor SOCKS port (default: 9050)
    --max-urls Maximum URLs to process (0 = unlimited)
    --delay Delay between requests (default: 1.0s)
    --deep-only Only process deep web URLs (.onion, .i2p, etc.)
    --checkpoint Checkpoint file (default: scrap_checkpoint.pkl)
    --restore Restore from checkpoint
    --no-checkpoint Disable checkpoint saving
    --db SQLite database file (default: scrap_data.db)
    
    Usage:
    
    ./forever_scrap.py -t site.com -o output.txt
    ./forever_scrap.py -t site.com -o output.txt --tor --deep-only
    ./forever_scrap.py -t site.com -o output.txt --restore
   ''')
    parser.exit(1)

# global List of Results
global_url = []
processed_urls = set()  # URLs já processadas
urls_to_process = []    # Fila de URLs para processar
urls_processed_count = 0  # Contador de URLs processadas
data_lock = threading.RLock()  # Sincroniza acesso às estruturas compartilhadas

# url base request
first_url = args.scrap_url
output_file_path = args.scrap_out_path
output_file_handle = None
output_file_append_mode = bool(args.restore and not args.scrap_out_path)
output_warning_emitted = False

# Gerenciar arquivo de saída
def prepare_output_file():
    global output_file_handle, output_warning_emitted
    if output_file_handle is not None:
        return True
    if not output_file_path:
        if not output_warning_emitted:
            print("[!] Nenhum arquivo de saída configurado. URLs não serão gravadas em arquivo.")
            output_warning_emitted = True
        return False
    mode = 'a' if output_file_append_mode else 'w'
    try:
        output_file_handle = open(output_file_path, mode, encoding='utf-8')
        return True
    except Exception as e:
        print(f"[!] Erro ao abrir arquivo de saída {output_file_path}: {e}")
        return False


def write_url_to_output(url):
    if not prepare_output_file():
        return False
    output_file_handle.write(url + '\n')
    output_file_handle.flush()
    return True

# Lista de domínios da deep web
DEEP_WEB_DOMAINS = [
    '.onion',      # Tor
    '.i2p',        # I2P
    '.loki',       # Loki
    '.zq',         # ZeroNet
    '.bit',        # Namecoin
    '.b32.i2p',    # I2P Base32
    '.onion.to',   # Onion.to (proxy)
    '.onion.cab',  # Onion.cab (proxy)
    '.onion.ws',   # Onion.ws (proxy)
    '.onion.ly',   # Onion.ly (proxy)
    '.onion.link', # Onion.link (proxy)
    '.onion.dog',  # Onion.dog (proxy)
    '.onion.city', # Onion.city (proxy)
    '.onion.pet',  # Onion.pet (proxy)
    '.onion.nu',   # Onion.nu (proxy)
    '.onion.com',  # Onion.com (proxy)
    '.onion.net',  # Onion.net (proxy)
    '.onion.org',  # Onion.org (proxy)
    '.onion.info', # Onion.info (proxy)
    '.onion.bz',   # Onion.bz (proxy)
    '.onion.co',   # Onion.co (proxy)
    '.onion.me',   # Onion.me (proxy)
    '.onion.sh',   # Onion.sh (proxy)
    '.onion.torproject.org', # Tor Project
]

# Inicializar banco de dados SQLite
def init_database():
    conn = sqlite3.connect(args.db_file)
    cursor = conn.cursor()
    
    # Criar tabela principal
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            status_code INTEGER,
            title TEXT,
            ip_address TEXT,
            server TEXT,
            cname TEXT,
            technologies TEXT,
            response_time REAL,
            content_length INTEGER,
            headers TEXT,
            discovered_from TEXT,
            is_deep_web BOOLEAN,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Criar índices para performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url ON urls(url)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON urls(status_code)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_deep_web ON urls(is_deep_web)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_processed_at ON urls(processed_at)')
    
    conn.commit()
    conn.close()
    print(f"[+] Banco de dados inicializado: {args.db_file}")

# Salvar URL no banco de dados
def save_url_to_db(url_data):
    conn = sqlite3.connect(args.db_file)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO urls 
            (url, status_code, title, ip_address, server, cname, technologies, 
             response_time, content_length, headers, discovered_from, is_deep_web)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            url_data['url'],
            url_data.get('status_code'),
            url_data.get('title'),
            url_data.get('ip_address'),
            url_data.get('server'),
            url_data.get('cname'),
            json.dumps(url_data.get('technologies', [])),
            url_data.get('response_time'),
            url_data.get('content_length'),
            json.dumps(url_data.get('headers', {})),
            url_data.get('discovered_from'),
            url_data.get('is_deep_web', False)
        ))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"[!] Erro ao salvar URL no banco: {e}")
        return False
    finally:
        conn.close()

# Extrair tecnologias do HTML
def extract_technologies(html_content, headers):
    technologies = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Verificar frameworks JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '')
            if 'jquery' in src.lower():
                technologies.append('jQuery')
            elif 'react' in src.lower():
                technologies.append('React')
            elif 'angular' in src.lower():
                technologies.append('Angular')
            elif 'vue' in src.lower():
                technologies.append('Vue.js')
        
        # Verificar meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content = meta.get('content', '').lower()
            
            if 'generator' in name:
                technologies.append(content)
            elif 'framework' in name:
                technologies.append(content)
        
        # Verificar headers
        server = headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        x_powered_by = headers.get('X-Powered-By', '')
        if x_powered_by:
            technologies.append(f"Powered-By: {x_powered_by}")
        
        # Verificar outras tecnologias comuns
        if 'wordpress' in html_content.lower():
            technologies.append('WordPress')
        if 'php' in headers.get('X-Powered-By', '').lower():
            technologies.append('PHP')
        if 'apache' in server.lower():
            technologies.append('Apache')
        if 'nginx' in server.lower():
            technologies.append('Nginx')
        if 'cloudflare' in server.lower():
            technologies.append('Cloudflare')
        
    except Exception as e:
        print(f"[!] Erro ao extrair tecnologias: {e}")
    
    return technologies

# Obter informações DNS
def get_dns_info(domain):
    dns_info = {'ip_address': None, 'cname': None}
    
    try:
        # Resolver IP
        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            dns_info['ip_address'] = str(answers[0])
        
        # Resolver CNAME
        try:
            cname_answers = dns.resolver.resolve(domain, 'CNAME')
            if cname_answers:
                dns_info['cname'] = str(cname_answers[0])
        except:
            pass
            
    except Exception as e:
        print(f"[!] Erro ao resolver DNS para {domain}: {e}")
    
    return dns_info

# Função para salvar checkpoint
def save_checkpoint():
    if args.no_checkpoint:
        return

    try:
        with data_lock:
            checkpoint_data = {
                'global_url': list(global_url),
                'processed_urls': list(processed_urls),
                'urls_to_process': list(urls_to_process),
                'urls_processed_count': urls_processed_count,
                'first_url': first_url,
                'output_file_path': output_file_path,
                'args': {
                    'scrap_url': args.scrap_url,
                    'use_tor': args.use_tor,
                    'tor_port': args.tor_port,
                    'deep_only': args.deep_only,
                    'max_urls': args.max_urls,
                    'delay': args.delay,
                    'num_threads': args.num_threads,
                    'scrap_out_path': output_file_path
                }
            }
            total_urls_snapshot = len(global_url)
            processed_snapshot = len(processed_urls)
            queue_snapshot = len(urls_to_process)

        temp_file = f"{args.checkpoint_file}.tmp"
        with open(temp_file, 'wb') as f:
            pickle.dump(checkpoint_data, f)

        os.replace(temp_file, args.checkpoint_file)

        print(f"[+] Checkpoint salvo: {args.checkpoint_file}")
        print(f"[+] Status: {total_urls_snapshot} URLs encontradas, {processed_snapshot} processadas, {queue_snapshot} na fila")

    except Exception as e:
        print(f"[!] Erro ao salvar checkpoint: {e}")

# Função para carregar checkpoint
def load_checkpoint():
    if not args.restore or not os.path.exists(args.checkpoint_file):
        return False

    try:
        with open(args.checkpoint_file, 'rb') as f:
            checkpoint_data = pickle.load(f)

        global global_url, processed_urls, urls_to_process, urls_processed_count, first_url
        global output_file_path, output_file_append_mode

        with data_lock:
            global_url = list(checkpoint_data.get('global_url', []))

            processed_data = checkpoint_data.get('processed_urls', [])
            if isinstance(processed_data, (list, tuple, set)):
                processed_urls = set(processed_data)
            else:
                processed_urls = set()

            urls_to_process = list(checkpoint_data.get('urls_to_process', []))
            urls_processed_count = checkpoint_data.get('urls_processed_count', 0)
            first_url = checkpoint_data.get('first_url', first_url)

            checkpoint_args = checkpoint_data.get('args', {})

            checkpoint_output_path = checkpoint_data.get('output_file_path') or checkpoint_args.get('scrap_out_path')
            if checkpoint_output_path and not output_file_path:
                output_file_path = checkpoint_output_path
                args.scrap_out_path = checkpoint_output_path
                output_file_append_mode = True

            for key, value in checkpoint_args.items():
                if key in {'scrap_out_path'}:
                    continue
                if not hasattr(args, key):
                    continue
                default_value = parser_defaults.get(key, None)
                current_value = getattr(args, key)
                if current_value == default_value or current_value is None:
                    setattr(args, key, value)

            if not args.scrap_url and 'scrap_url' in checkpoint_args:
                args.scrap_url = checkpoint_args['scrap_url']
                first_url = checkpoint_args['scrap_url']

            total_urls_snapshot = len(global_url)
            processed_snapshot = len(processed_urls)
            queue_snapshot = len(urls_to_process)

        print(f"[+] Checkpoint restaurado: {args.checkpoint_file}")
        print(f"[+] Status restaurado: {total_urls_snapshot} URLs encontradas, {processed_snapshot} processadas, {queue_snapshot} na fila")

        return True

    except Exception as e:
        print(f"[!] Erro ao carregar checkpoint: {e}")
        return False

# Função para verificar se é deep web
def is_deep_web_url(url):
    """Verifica se a URL é da deep web"""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        # Verificar se contém domínios da deep web
        for domain in DEEP_WEB_DOMAINS:
            if domain in hostname:
                return True
        
        # Verificar se é um hash .onion (56 caracteres + .onion)
        if '.onion' in hostname:
            onion_part = hostname.split('.onion')[0]
            if len(onion_part) >= 56:  # Hash .onion v3
                return True
            elif len(onion_part) == 16:  # Hash .onion v2
                return True
        
        return False
    except:
        return False

# Função para filtrar URLs
def filter_urls(urls):
    """Filtra URLs baseado nas configurações"""
    if not args.deep_only:
        return urls  # Retorna todas se não estiver em modo deep-only
    
    filtered = []
    for url in urls:
        if is_deep_web_url(url):
            filtered.append(url)
        else:
            print(f"[!] Ignorando URL da surface web: {url}")
    
    return filtered

# Configurar DNS do Tor se necessário
def setup_tor_dns():
    if args.use_tor:
        try:
            # Configurar socket para usar Tor SOCKS para DNS
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", args.tor_port)
            socket.socket = socks.socksocket
            print(f"[+] DNS configurado para usar Tor na porta {args.tor_port}")
            return True
        except Exception as e:
            print(f"[!] Erro ao configurar DNS do Tor: {e}")
            return False
    return True

# Configurar retry strategy
def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# Função para testar conectividade com domínio .onion
def test_onion_connectivity(domain):
    if args.use_tor and '.onion' in domain:
        try:
            # Testar resolução DNS via Tor
            parsed = urlparse(domain)
            hostname = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
            
            print(f"[*] Testando conectividade com {hostname} via Tor...")
            
            # Tentar resolver o hostname via Tor
            test_socket = socks.socksocket()
            test_socket.set_proxy(socks.SOCKS5, "127.0.0.1", args.tor_port)
            test_socket.settimeout(30)
            
            port = 80 if parsed.scheme == 'http' else 443
            test_socket.connect((hostname, port))
            test_socket.close()
            
            print(f"[+] Conectividade com {hostname} OK")
            return True
            
        except Exception as e:
            print(f"[!] Erro ao testar conectividade com {hostname}: {e}")
            return False
    return True

# request and return html with detailed info
def resq_urls(url_x):
    headers = {
        'authorization': f'{args.scrap_auth}',
        'cookie': f'{args.scrap_cookie}',
        'user-agent': f'{args.scrap_user_agent}'
    }
    
    # Remover valores None dos headers
    headers = {k: v for k, v in headers.items() if v is not None}
    
    session = create_session()
    
    try:
        start_time = time.time()
        
        # Configuração de proxy baseada nas opções
        if args.use_tor:
            # Usar Tor via SOCKS
            proxy = {
                'http': f'socks5h://127.0.0.1:{args.tor_port}',
                'https': f'socks5h://127.0.0.1:{args.tor_port}'
            }
            
            # Testar conectividade se for domínio .onion
            if '.onion' in url_x:
                if not test_onion_connectivity(url_x):
                    print(f"[!] Não foi possível conectar com {url_x}")
                    return None
            
            response = session.get(url_x, proxies=proxy, verify=False, headers=headers, timeout=60)
        elif args.scrap_proxy is not None:
            # Usar proxy customizado
            proxy = {'http': f'{args.scrap_proxy}', 'https': f'{args.scrap_proxy}'}
            response = session.get(url_x, proxies=proxy, verify=False, headers=headers, timeout=30)
        else:
            # Sem proxy
            response = session.get(url_x, verify=False, headers=headers, timeout=30)
        
        end_time = time.time()
        response_time = end_time - start_time
        
        # Extrair informações detalhadas
        parsed_url = urlparse(url_x)
        domain = parsed_url.netloc
        
        # Obter informações DNS
        dns_info = get_dns_info(domain)
        
        # Extrair título
        title = ""
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.get_text().strip()
        except:
            pass
        
        # Extrair tecnologias
        technologies = extract_technologies(response.text, response.headers)
        
        # Preparar dados para salvar
        url_data = {
            'url': url_x,
            'status_code': response.status_code,
            'title': title,
            'ip_address': dns_info['ip_address'],
            'server': response.headers.get('Server', ''),
            'cname': dns_info['cname'],
            'technologies': technologies,
            'response_time': response_time,
            'content_length': len(response.content),
            'headers': dict(response.headers),
            'discovered_from': None,  # Será preenchido quando descoberta
            'is_deep_web': is_deep_web_url(url_x)
        }
        
        # Salvar no banco de dados
        save_url_to_db(url_data)
        
        return {
            'text': response.text,
            'data': url_data
        }
            
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Erro de conexão para {url_x}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout para {url_x}: {e}")
        return None
    except Exception as e:
        print(f"[!] Erro inesperado para {url_x}: {e}")
        return None

# Def find URL in pag - COM FILTRO DE DEEP WEB
def find_url(response_x, source_url):
    if not response_x:
        return
    comp = re.compile(
        "https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)")
    x = re.findall(comp, response_x)

    # Filtrar URLs se estiver em modo deep-only
    if args.deep_only:
        x = filter_urls(x)

    new_urls = 0
    with data_lock:
        for url in x:
            if url not in global_url:
                global_url.append(url)
                if url not in processed_urls and url not in urls_to_process:
                    urls_to_process.append(url)
                    new_urls += 1

    if new_urls > 0:
        print(f"[+] Encontradas {new_urls} novas URLs em {source_url}")

# Def get HREF - COM FILTRO DE DEEP WEB
def find_href(response_x, source_url):
    if not response_x:
        return
    comp_href = re.compile(r'href=[\'"]?([^\'" >]+)')
    x = re.findall(comp_href, response_x)
    new_urls = 0
    
    urls_to_add = []
    for href in x:
        if href.startswith('http'):
            candidate_url = href
        else:
            parsed_source = urlparse(source_url)
            if href.startswith('/'):
                candidate_url = f"{parsed_source.scheme}://{parsed_source.netloc}{href}"
            else:
                candidate_url = f"{parsed_source.scheme}://{parsed_source.netloc}/{href}"

        if args.deep_only and not is_deep_web_url(candidate_url):
            print(f"[!] Ignorando href da surface web: {candidate_url}")
            continue

        urls_to_add.append(candidate_url)

    with data_lock:
        for url in urls_to_add:
            if url not in global_url:
                global_url.append(url)
                if url not in processed_urls and url not in urls_to_process:
                    urls_to_process.append(url)
                    new_urls += 1
    
    if new_urls > 0:
        print(f"[+] Encontradas {new_urls} novas URLs (href) em {source_url}")

# Processar uma URL individual
def process_single_url(url):
    global urls_processed_count

    with data_lock:
        if url in processed_urls:
            return

        if args.deep_only and not is_deep_web_url(url):
            print(f"[!] Ignorando URL da surface web: {url}")
            processed_urls.add(url)
            return

        processed_urls.add(url)
        urls_processed_count += 1
        current_count = urls_processed_count

    print(f"[*] Processando: {url}")

    time.sleep(args.delay)

    response_data = resq_urls(url)
    if response_data:
        find_url(response_data['text'], url)
        find_href(response_data['text'], url)
        with data_lock:
            write_url_to_output(url)
            total_urls_snapshot = len(global_url)
            queue_snapshot = len(urls_to_process)
        print(f"[+] Processado: {url} - Status: {response_data['data']['status_code']} - Title: {response_data['data']['title'][:50]}...")
        print(f"[+] Total URLs: {total_urls_snapshot} - Fila: {queue_snapshot}")

        if current_count % 10 == 0:
            save_checkpoint()
    else:
        print(f"[!] Falha ao processar: {url}")

# Verificar se o Tor está funcionando
def check_tor():
    if args.use_tor:
        try:
            test_url = "https://check.torproject.org/"
            proxy = {
                'http': f'socks5://127.0.0.1:{args.tor_port}',
                'https': f'socks5://127.0.0.1:{args.tor_port}'
            }
            response = requests.get(test_url, proxies=proxy, timeout=10)
            if "Congratulations" in response.text:
                print(f"[+] Tor está funcionando corretamente na porta {args.tor_port}")
                return True
            else:
                print(f"[!] Tor pode não estar funcionando corretamente")
                return False
        except Exception as e:
            print(f"[!] Erro ao verificar Tor: {e}")
            print(f"[!] Certifique-se de que o Tor está rodando na porta {args.tor_port}")
            return False
    return True

# Inicializar banco de dados
init_database()

checkpoint_loaded = False
if args.restore:
    if load_checkpoint():
        checkpoint_loaded = True
        print("[+] Continuando de onde parou...")
    else:
        print("[!] Não foi possível restaurar checkpoint. Iniciando do zero...")
        if not args.scrap_url:
            print("[!] Forneça -t/--scrap_url para iniciar sem checkpoint.")
            parser.exit(1)

# Reconfigurar parâmetros críticos após restore
if not checkpoint_loaded:
    first_url = args.scrap_url
    if args.deep_only and first_url and not is_deep_web_url(first_url):
        print(f"[!] AVISO: URL inicial não é da deep web: {first_url}")
        print("[!] Continuando mesmo assim...")

# Configurar Tor DNS antes de tudo (pode ter sido ajustado no restore)
if args.use_tor:
    setup_tor_dns()

# Verificar Tor antes de começar
if not check_tor():
    print("[!] Continuando mesmo com problemas no Tor...")

# Inicializar fila se não veio do checkpoint
if not checkpoint_loaded:
    if not first_url:
        print("[!] Nenhuma URL inicial disponível. Abortando.")
        parser.exit(1)
    urls_to_process.append(first_url)

if output_file_path:
    if not prepare_output_file():
        parser.exit(1)

print(f"[*] Iniciando scraping contínuo de: {first_url}")
print(f"[*] Configurações: Threads={args.num_threads}, Delay={args.delay}s, Max URLs={'Ilimitado' if args.max_urls == 0 else args.max_urls}")
if args.deep_only:
    print(f"[*] Modo DEEP-ONLY ativado - apenas URLs da deep web serão processadas")

# Loop principal de scraping contínuo
while True:
    with data_lock:
        continue_condition = bool(urls_to_process) and (args.max_urls == 0 or urls_processed_count < args.max_urls)
        if not continue_condition:
            break

        current_batch = urls_to_process[:args.num_threads]
        urls_to_process = urls_to_process[args.num_threads:]

    if not current_batch:
        break

    print(f"[*] Processando lote de {len(current_batch)} URLs...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.num_threads) as executor:
        future_to_url = {executor.submit(process_single_url, url): url for url in current_batch}
        concurrent.futures.wait(future_to_url)

    with data_lock:
        processed_snapshot = urls_processed_count
        queue_snapshot = len(urls_to_process)

    print(f"[*] Progresso: {processed_snapshot} URLs processadas, {queue_snapshot} na fila")

    if not args.no_checkpoint:
        save_checkpoint()

    with data_lock:
        if not urls_to_process:
            print("[!] Nenhuma nova URL encontrada. Parando...")
            break

with data_lock:
    all_urls_snapshot = list(global_url)
    processed_total_snapshot = urls_processed_count

print(f"\n[+] Scraping concluído!")
print(f"[+] Total de URLs encontradas: {len(all_urls_snapshot)}")
print(f"[+] Total de URLs processadas: {processed_total_snapshot}")

with open('all_urls.txt', 'w') as f:
    for url in all_urls_snapshot:
        f.write(url + '\n')

if output_file_handle:
    output_file_handle.close()

print(f"[+] Todas as URLs salvas em 'all_urls.txt'")
print(f"[+] Dados detalhados salvos em: {args.db_file}")

# Salvar checkpoint final
if not args.no_checkpoint:
    save_checkpoint()
    print(f"[+] Checkpoint final salvo: {args.checkpoint_file}")

# Mostrar estatísticas do banco
conn = sqlite3.connect(args.db_file)
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM urls')
total_urls = cursor.fetchone()[0]
cursor.execute('SELECT COUNT(*) FROM urls WHERE is_deep_web = 1')
deep_web_urls = cursor.fetchone()[0]
cursor.execute('SELECT COUNT(*) FROM urls WHERE status_code = 200')
successful_urls = cursor.fetchone()[0]
conn.close()

print(f"[+] Estatísticas do banco:")
print(f"    - Total de URLs: {total_urls}")
print(f"    - Deep web: {deep_web_urls}")
print(f"    - Status 200: {successful_urls}")
