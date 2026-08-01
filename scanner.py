from datetime import datetime, timezone
from urllib import response
import requests
import socket
import re
import math
import urllib.parse
import posixpath
import concurrent.futures
import threading
import time as t
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from api_integrations import (
    check_virustotal, check_shodan,
    check_google_safe_browsing, check_hibp_domain,
    check_nvd_cves, check_dns_security, check_ssl_details
)
import difflib
import tldextract
from collections import deque
import html
from urllib.parse import urlparse
from urllib3.util.retry import Retry

requests.packages.urllib3.disable_warnings()

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 2049, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]

PORT_META = {
    21: ('FTP', 'high'), 22: ('SSH', 'medium'), 23: ('Telnet', 'critical'), 25: ('SMTP', 'low'),
    53: ('DNS', 'low'), 80: ('HTTP', 'low'), 110: ('POP3', 'medium'), 135: ('RPC', 'high'),
    143: ('IMAP', 'medium'), 443: ('HTTPS', 'info'), 445: ('SMB', 'critical'), 465: ('SMTPS', 'low'),
    587: ('SMTP-Sub', 'low'), 993: ('IMAPS', 'info'), 995: ('POP3S', 'info'), 1433: ('MSSQL', 'critical'),
    1521: ('Oracle', 'critical'), 2049: ('NFS', 'high'), 3306: ('MySQL', 'critical'),
    3389: ('RDP', 'critical'), 4444: ('Metasploit', 'critical'), 5432: ('PostgreSQL', 'critical'),
    5900: ('VNC', 'critical'), 6379: ('Redis', 'critical'), 8080: ('HTTP-Alt', 'medium'),
    8443: ('HTTPS-Alt', 'low'), 8888: ('HTTP-Dev', 'medium'), 9200: ('Elasticsearch', 'critical'),
    27017: ('MongoDB', 'critical'),
}

# Parameters that are never injectable
SKIP_PARAMS = {
    'submit', 'change', 'login', 'send', 'token', 'user_token',
    'csrf', 'csrfmiddlewaretoken', 'authenticity_token', 'nonce',
    '__requestverificationtoken', '__viewstate', '__eventvalidation',
    'button', 'action', 'btnsubmit', 'btnlogin', 'btnregister',
    'btnchange', 'sign_in', 'log_in', 'go',
    'password', 'password_new', 'password_conf', 'pass_conf',
    'confirm_password', 'remember', 'remember_me',
    'redirect', 'returnurl', 'next',
    'search_by'
}

# Extensions that are not scannable targets
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf",".mp4", ".mp3",
    ".avi",".pdf", ".zip", ".rar", ".7z",
}

# SQL error patterns — must be DB-engine-specific, never generic words
SQL_ERROR_PATTERNS = (
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?_",
    r"mysql_fetch_array\(\)",
    r"mysqli_sql_exception",
    r"pg_query\(\).*failed",
    r"psql.*error",
    r"sqlite3?\.operationalerror",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"ora-\d{4,5}:",
    r"odbc sql server driver.*\[sql server\]",
    r"supplied argument is not a valid mysql",
    r"column count doesn't match value count at row",
    r"mysql_num_rows\(",
    r"mysql_fetch_assoc\(",
    r"pdoexception",
    r"sqlstate\[[a-z0-9]+\]",
    r"syntax error at or near",
    r"postgresql.*error",
    r"fatal error.*mysql",
    r"unknown column",
    r"unknown table",
    r"division by zero",
    r"invalid input syntax",
    r"incorrect syntax near",
    r"sql syntax.*mysql",
)

SQL_ERROR_PAYLOADS = (
    "'",
    '"',
    "')",
    "';",
    "' OR '1'='1",
    '" OR "1"="1',
    "'--",
    "' OR 1=1--",
    '" OR 1=1--',
)

SQL_BOOLEAN_PAYLOADS = (
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" OR 1=1--", " OR 1=2--"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ('" OR "1"="1"--', '" OR "1"="2"--'),
    (") AND (1=1", ") AND (1=2"),
    ("')) AND (('1'='1", "')) AND (('1'='2"),
)

SQL_TIME_PAYLOADS = (
    ("MySQL", "' AND SLEEP(3)-- "),
    ("PostgreSQL", "';SELECT pg_sleep(3)--"),
    ("MSSQL", "';WAITFOR DELAY '0:0:3'--"),
    ("Oracle", "';DBMS_LOCK.SLEEP(3)--"),
)

CSRF_TOKEN_NAMES = {
    'csrf',
    '_csrf',
    '_token',
    'csrf_token',
    'authenticity_token',
    'nonce',
    '__requestverificationtoken',
    'csrfmiddlewaretoken',
}

XSS_PAYLOADS = (
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    '"><svg/onload=alert(1)>',
    "'><svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<input type=text value='><script>alert(1)</script>'>",
    "<textarea><script>alert(1)</script></textarea>",
    "<div style='display:none'><script>alert(1)</script></div>",
    "<object data='javascript:alert(1)'></object>",
    "<embed src='javascript:alert(1)'></embed>",
    "<link rel='stylesheet' href='javascript:alert(1)'>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
)

SSTI_PAYLOADS = (
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%=7*7%>", "49"),
    ("{{1337-1288}}", "49"),
    ("{{7*'7'}}", "7777777"),
)

LFI_PAYLOADS = (
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
)

BLACKLIST_PATHS = {
    "logout",
    "signout",
    "logoff"
}

FILE_PARAMS = {
    'file',
    'path',
    'page',
    'template',
    'include',
    'view',
    'download',
    'document',
    'doc',
    'filename',
}

# Params likely to interact with database queries
DB_PARAM_HINTS = {
    'id', 'uid', 'userid', 'user_id', 'item', 'product_id', 'cat', 'category',
    'page', 'pid', 'nid', 'aid', 'article', 'post', 'news', 'blog', 'entry',
    'record', 'row', 'key', 'ref', 'query', 'search', 'q', 'name', 'username',
    'user', 'email', 'title', 'type', 'order', 'sort','uuid','guid','doc',
    'document','file','filename','slug','lang','locale','filter','keyword','tag',
    'author','date','month','year','comment','message','text','value','code','number',
    'invoice','order_id','customer','customer_id'
}

# URL path segments that suggest a DB-backed endpoint
DB_PATH_HINTS = {
    'sqli', 'sql', 'login', 'search', 'product', 'item', 'article', 'news',
    'blog', 'post', 'user', 'profile', 'account', 'view', 'detail',
    'vulnerabilities', 'dvwa', 'api','graphql','rest','orders','customers',
    'invoices','comments','messages','tickets','files','documents',
    'download','upload','api/v1','api/v2'
}

# Domains that are known-benign — skip aggressive injection tests
TRUSTED_DOMAINS = {
    'google.com', 'google.co.in', 'google.co.uk', 'google.com.au',
    'facebook.com', 'twitter.com', 'x.com', 'instagram.com',
    'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'youtube.com', 'wikipedia.org', 'cloudflare.com', 'github.com',
}

SENSITIVE_FILES = [
    ('/.env.local', 'Environment File', 'critical'),
    ('/.env.production', 'Environment File', 'critical'),
    ('/.env.dev', 'Environment File', 'critical'),
    ('/docker-compose.yml', 'Docker Compose', 'medium'),
    ('/Dockerfile', 'Dockerfile', 'low'),
    ('/.git/config', 'Git Config', 'high'),
    ('/.svn/entries', 'SVN Repository', 'high'),
    ('/.hg/hgrc', 'Mercurial Repository', 'high'),
    ('/config.json', 'Configuration File', 'medium'),
    ('/config.yml', 'Configuration File', 'medium'),
    ('/config.yaml', 'Configuration File', 'medium'),
    ('/backup.zip', 'Backup Archive', 'critical'),
    ('/backup.tar.gz', 'Backup Archive', 'critical'),
    ('/backup.rar', 'Backup Archive', 'critical'),
    ('/db.sql', 'Database Backup', 'critical'),
    ('/dump.sql', 'Database Dump', 'critical'),
    ('/debug', 'Debug Endpoint', 'medium'),
    ('/actuator', 'Spring Boot Actuator', 'high'),
    ('/actuator/env', 'Spring Boot Env', 'critical'),
    ('/actuator/health', 'Spring Boot Health', 'low'),
    ('/swagger', 'Swagger UI', 'low'),
    ('/swagger-ui/', 'Swagger UI', 'low'),
    ('/openapi.json', 'OpenAPI Spec', 'low'),
]

FILE_SIGNATURES = {
    '.env': ['APP_KEY=', 'DB_PASSWORD=', 'DATABASE_URL=', 'SECRET_KEY='],
    '.git/HEAD': ['ref: refs/heads/'],
    'config.php': ['$db_host', '$db_user', '$db_pass', 'mysqli_connect(', 'PDO('],
    'wp-config.php': ['DB_NAME', 'DB_PASSWORD', '$table_prefix'],
    'phpinfo.php': ['<title>phpinfo()', 'PHP Version', 'Zend Engine', 'php credits'],
    'web.config': ['<configuration', '<system.web', '<system.webServer'],
    'backup.sql': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE'],
    'database.sql': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE'],
    '.bash_history': ['sudo ', 'ssh ', 'mysql ', 'curl '],
    'id_rsa': ['-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----'],
    '.git/config': ['[core]', '[remote "origin"]'],
    'docker-compose.yml': ['services:', 'version:'],
    'Dockerfile': ['FROM ', 'RUN ', 'CMD '],
    'config.json': ['{'],
    'config.yml': [':'],
    '.env.local': ['APP_KEY=', 'DATABASE_URL='],
}

WAF_SIGNATURES = {
    'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status'],
    'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
    'Akamai': ['akamai', 'x-akamai-request-id'],
    'Sucuri': ['x-sucuri-id', 'sucuri'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'Imperva': ['incapsula', 'x-iinfo'],
    'Barracuda': ['barra_counter_session'],
    'F5 BIG-IP': ['bigip', 'f5'],
    'Azure Front Door': ['x-azure-ref'],
    'Fastly': ['x-served-by', 'fastly'],
    'FortiWeb': ['fortiwafsid'],
    'Citrix ADC': ['citrix'],
    'DenyAll': ['denyall'],
    'Reblaze': ['reblaze'],
    'StackPath': ['stackpath'],
}

ROBOTS_SENSITIVE_HINTS = [
    '/admin', '/backup', '/internal', '/private', '/dashboard', '/config',
    '/api', '/api/v1', '/graphql', '/swagger', '/actuator', '/debug',
    '/staging', '/dev', '/test', '/old', '/backup', '/logs', '/uploads', '/tmp'
]

CVSS_BY_SEVERITY = {
    'critical': '9.1',
    'high': '7.5',
    'medium': '5.3',
    'low': '3.1',
    'info': '0.0',
}

SEVERITY_WEIGHTS = {
    'critical': 35,
    'high': 25,
    'medium': 15,
    'low': 10,
    'info': 0,
}

CONFIDENCE_WEIGHTS = {
    'high': 1.0,
    'medium': 0.6,
    'low': 0.3,
}

DEFAULT_TIMEOUT = 10  # seconds

DEFAULT_PARAM_VALUE = '1'

SKIP_PARAM_VALUES = (
    "submit",
    "login",
    "send",
    "change",
    "go",
    "search",
)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/139.0.0.0 Safari/537.36 "
    "VulnScanner/1.0"
)

COOKIE_ATTRIBUTES = {
    "path",
    "secure",
    "httponly",
    "samesite",
    "domain",
    "expires",
    "max-age"
}

LOGOUT_PATHS = (
    "/logout",
    "/logoff",
    "/signout",
    "/sign-out",
    "/signoff",
)

SRI_CDN_HINTS = (
    "cdnjs.",
    "jsdelivr.",
    "unpkg.",
    "code.jquery.com",
    "ajax.googleapis.com",
    "bootstrapcdn.",
    "stackpath.",
    "cdn."
)

from urllib3.util.retry import Retry

class _TimeoutAdapter(HTTPAdapter):
    """HTTPAdapter that applies a default timeout to all requests."""

    def __init__(self, timeout=DEFAULT_TIMEOUT, *args, **kwargs):
        self._timeout = float(timeout)
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        kwargs.setdefault("timeout", self._timeout)
        return super().send(request, **kwargs)


class VulnScanner:

    def __init__(self, url, options=None):
        self.url = self._normalize_url(url)
        
        self.opts = {
            "max_pages": 20,
            "timeout": DEFAULT_TIMEOUT,
            "crawl": True,
            "port_scan": True,
            "aggressive": False,
            **(options or {}),
        }
        
        self.parsed = urllib.parse.urlparse(self.url)
        self.hostname = self.parsed.hostname or ""
        self.is_trusted = self._is_trusted_domain(self.url)
        
        # HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        })
        self.session.verify = False
        
        retry = Retry(
            total=2,
            connect=2,
            read=1,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
        )
        
        adapter = _TimeoutAdapter(
            timeout=self.opts["timeout"],
            max_retries=retry,
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Scan results
        self.results = {
            "vulnerabilities": [],
            "ports": [],
            "technologies": [],
            "dns_security": {},
            "ssl_info": {},
            "waf": None,
            "threat_intel": {},
            "auth": {
                "mode": (self.opts.get("auth") or {}).get("mode", "none"),
                "status": "not_attempted",
            },
            "score": 0,
        }
        
        # Internal state
        self.discovered_urls = []
        self._vuln_ids = set()
        self._vuln_lock = threading.Lock()
        
    # ─────────────────────────────────────────────────────────────────────────
    def _is_trusted_domain(self, url):
        """
        Returns True if the URL belongs to a trusted domain.
        Matches both root domains and subdomains.
        """
        hostname = (urllib.parse.urlparse(url).hostname or "").lower()
        
        return any(
            hostname == domain.lstrip(".") or hostname.endswith(domain)
            for domain in TRUSTED_DOMAINS
        )
        
    # ─────────────────────────────────────────────────────────────────────────
    
    def _perform_authentication(self):
        auth = self.opts.get("auth") or {}
        mode = (auth.get('mode') or 'none').lower()
        self.results['auth'].update(mode=mode, status='not_attempted', detail='')
        
        if mode == 'none':
            self.results["auth"]["status"] = "disabled"
            return
        
        if mode == 'cookie':
            self._apply_session_cookie(auth)
        elif mode == 'credentials':
            self._login_with_credentials(auth)
        else:
            self.results['auth'].update(status='error', detail=f'Unknown auth mode: {mode}')
            
        print(f"[Auth] {self.results['auth']['status']}: {self.results['auth'].get('detail', '')}", flush=True)
        
    def _apply_session_cookie(self, auth): # Applies cookies from a string to the session
        
        cookie_str = (auth.get('cookie') or '').strip()
        if not cookie_str:
            self.results['auth'].update(status='error', detail='No cookie value provided')
            return
        
        applied = []
        for part in cookie_str.split(";"):
            if '=' not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            value = value.strip().strip('"')
            if not name:
                continue
            self.session.cookies.set(name, value)
            applied.append(name)
            
        if applied:
            self.results['auth'].update(
                status='success',
                detail=f"{len(applied)} cookies loaded",
                cookie_names=applied,
            )
        else:
            self.results['auth'].update(status='error', detail='No valid cookies could be parsed')
            
    def _find_login_form(self, soup): # Returns the form that most likely represents authentication
        forms = soup.find_all('form')
        candidate = [form for form in forms if form.find('input', {'type': 'password'})]
        
        if not candidate:
            return None
        
        keywords = ('login', 'signin', 'sign-in', 'log-in', 'auth', 'username', 'password')
        
        def score(form):
            score = 0
            text = ' '.join(str(form.get(attr, '')) for attr in ('action', 'id', 'class')).lower()
            
            if any(k in text for k in keywords):
                score += 10
            
            if form.find('input', {'type': 'password'}):
                score += 1
                
            return score
        
        candidate.sort(key=score, reverse=True)
        return candidate[0]
    
    def _build_login_payload(self, form, auth): # Payload builder for login forms, preserving hidden fields and identifying username/password fields
        
        payload = {}
        user_field = (auth.get('username_field') or '').strip() or None
        pass_field = (auth.get('password_field') or '').strip() or None
        username_hints = ('user', 'email', 'login', 'account', 'name')
        
        for inp in form.find_all(['input', 'select', 'textarea']):
            name = inp.get('name')
            if not name:
                continue
            input_type = (inp.get("type") or "text").lower()
            
            if input_type == 'password':
                if not pass_field:
                    pass_field = name
                continue  # never prefill — real password is set by the caller
            
            if not user_field and input_type in ('text', 'email') and any(h in name.lower() for h in username_hints):
                user_field = name
                continue
            
            if input_type in ('checkbox', 'radio'):
                if inp.has_attr('checked'):
                    payload[name] = inp.get('value', 'on')
                continue
            
            payload[name] = inp.get('value', '')  # preserves CSRF tokens, etc.
            
        if not user_field:
            for inp in form.find_all('input'):
                if ((inp.get("type") or "text").lower() in ("text", "email") and inp.get("name")):
                    user_field = inp['name']
                    break
                
        return user_field, pass_field, payload
    
    def _verify_login_success(self, response): # Best-effort login verification
        
        if response.status_code >= 400:
            return False, f'HTTP {response.status_code}'
        
        body_lower = response.text.lower()
        failure_markers = (
            "invalid username",
            "invalid password",
            "incorrect password",
            "incorrect username",
            "login failed",
            "authentication failed",
            "invalid credentials",
            "wrong password",
            "access denied",
        )
        if any(m in body_lower for m in failure_markers):
            return False, 'Authentication failed'
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find("input", {"type": "password"}) is not None
        except Exception:
            pass
        
        cookies = len(self.session.cookies)
        
        redirected = response.history != []
        
        if cookies and not login_form:
            return True, 'Authenticated successfully'
        if redirected and not login_form:
            return True, 'Redirected after login'
        if cookies:
            return True, 'Session cookie detected'
        return False, 'Unable to verify authentication'
    
    def _login_with_credentials(self, auth):
        username = (auth.get('username') or '').strip()
        password = auth.get('password') or ''
        login_url = (auth.get('login_url') or self.url).strip()
        
        if not username or not password:
            self.results['auth'].update(status='error', detail='Username and password are required')
            return
        
        try:
            login_page = self.session.get(login_url, allow_redirects=True)
        except requests.RequestException as e:
            self.results['auth'].update(status='error', detail=f'Unable to load login page: {e}')
            return
        
        soup = BeautifulSoup(login_page.text, 'html.parser')
        form = self._find_login_form(soup)
        if not form:
            self.results['auth'].update(
                status='error',
                detail=f'Login form not found on {login_url}',
            )
            return
        
        action = urllib.parse.urljoin(login_page.url, form.get('action') or login_page.url)
        method = (form.get('method') or 'post').strip().lower()
        
        user_field, pass_field, payload = self._build_login_payload(form, auth)
        if not user_field or not pass_field:
            self.results['auth'].update(
                status='error',
                detail='Could not identify username/password field names — try setting them manually',
            )
            return
        
        payload[user_field] = username
        payload[pass_field] = password
        
        try:
            if method == 'get':
                response = self.session.get(action, params=payload, allow_redirects=True)
            else:
                response = self.session.post(action, data=payload, allow_redirects=True)
        except requests.RequestException as e:
            self.results['auth'].update(status='error', detail=f'Login request failed: {e}')
            return
        
        success, reason = self._verify_login_success(response)
        self.results['auth'].update(
            status='success' if success else 'failed',
            detail=reason,
            login_url=action,
            username_field=user_field,
            cookies_set=len(self.session.cookies),
            response_code=response.status_code,
            final_url=response.url,
        )
        
    # ─────────────────────────────────────────────────────────────────────────
    
    def _add(self, vuln): # Thread-safe vulnerability registration with deduplication
        
        vuln.setdefault('id', 'UNKNOWN')
        vuln.setdefault('category', 'general')
        vuln.setdefault('name', 'Unnamed Vulnerability')
        vuln.setdefault('severity', 'info')
        vuln.setdefault('confidence', 'medium')
        vuln.setdefault('description', '')
        vuln.setdefault('impact', '')
        vuln.setdefault('recommendation', '')
        vuln.setdefault('evidence', '')
        vuln.setdefault('cvss', '0.0')
        
        vuln['severity'] = vuln['severity'].lower()
        vuln['confidence'] = vuln['confidence'].lower()
        
        vuln['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        uid = (vuln.get('name'), vuln.get('name'), vuln.get('evidence'))
        
        with self._vuln_lock:
            if uid not in self._vuln_ids:
                return
            
            self._vuln_ids.add(uid)
            self.results['vulnerabilities'].append(vuln)
            
    # ─────────────────────────────────────────────────────────────────────────
    
    def _normalize_url(self, url): # Normalizes a URL to a canonical form for consistent comparison and deduplication
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        parsed = urllib.parse.urlparse(url)
        
        scheme = parsed.scheme.lower()
        
        hostname = (parsed.hostname or "").lower()
        
        port = parsed.port
        
        if (scheme == "http" and port == 80) or \
        (scheme == "https" and port == 443):
            netloc = hostname
        elif port:
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname
            
        path = posixpath.normpath(parsed.path or "/")
        
        if not path.startswith("/"):
            path = "/" + path
            
        if path != "/":
            path = path.rstrip("/")
            
        return urllib.parse.urlunparse((
            scheme,
            netloc,
            path,
            "",
            parsed.query,
            ""
        ))
        
    # ─────────────────────────────────────────────────────────────────────────
    
    def _crawl(self, max_pages=20, max_depth=3): # Crawls the target website to discover internal links and form actions, returning a list of discovered URLs
        
        discovered = []
        visited = set()
        seen = set()
        
        queue = deque([(self.url, 0)])
        
        seen.add(self._normalize_url(self.url))
        
        while queue and len(discovered) < max_pages:
            current, depth = queue.popleft()
            if depth > max_depth:
                continue
            
            try:
                r = self.session.get(
                    current,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True
                )
            except requests.RequestException:
                continue
            
            if r.status_code >= 400:
                continue
            
            # Ensure redirects stay inside the target domain
            redirected = urllib.parse.urlparse(r.url)
            
            if redirected.netloc.lower() != self.parsed.netloc.lower():
                continue
            
            current = self._normalize_url(r.url)
            
            if current in visited:
                continue
            
            visited.add(current)
            
            content_type = r.headers.get("Content-Type", "").lower()
            
            if not (content_type.startswith("text/html") or content_type.startswith("application/xhtml+xml")):
                continue
            
            discovered.append(current)
            
            soup = BeautifulSoup(r.text, "html.parser")
            
            for tag in soup.find_all("a", href=True): # Collect hyperlinks
                
                href = tag["href"].strip()
                
                if not href:
                    continue
                
                if href.startswith(("mailto:","javascript:","tel:","data:","ftp:")):
                    continue
                
                href = urllib.parse.urljoin(current, href)
                
                # Remove fragment (#section)
                href = urllib.parse.urldefrag(href).url
                
                parsed = urllib.parse.urlparse(href)
                
                # Internal links only
                if parsed.netloc.lower() != self.parsed.netloc.lower():
                    continue
                
                # Never crawl logout pages
                if any(
                    parsed.path.lower().endswith(p)
                    for p in LOGOUT_PATHS
                ):
                    continue
                
                filename = parsed.path.split("/")[-1].lower()
                
                if "." in filename:
                    ext = "." + filename.rsplit(".", 1)[-1]
                    if ext in SKIP_EXTENSIONS:
                        continue
                    
                if any(x in parsed.path.lower() for x in BLACKLIST_PATHS):
                    continue
                
                # Ignore query parameters during crawling
                crawl_url = urllib.parse.urlunparse((parsed.scheme,parsed.netloc,parsed.path,"","",""))
                
                crawl_url = self._normalize_url(crawl_url)
                
                if crawl_url not in seen:
                    seen.add(crawl_url)
                    queue.append((crawl_url, depth + 1))
                    
            for form in soup.find_all("form"): # Collect form actions
                
                action = form.get("action")
                
                if not action:
                    continue
                
                action = urllib.parse.urljoin(current, action)
                action = urllib.parse.urldefrag(action).url
                
                parsed = urllib.parse.urlparse(action)
                
                if parsed.netloc.lower() != self.parsed.netloc.lower():
                    continue
                
                if any(
                    parsed.path.lower().endswith(p)
                    for p in LOGOUT_PATHS
                ):
                    continue
                
                crawl_url = urllib.parse.urlunparse((parsed.scheme,parsed.netloc,parsed.path,"","",""))
                
                crawl_url = self._normalize_url(crawl_url)
                
                if crawl_url not in seen:
                    seen.add(crawl_url)
                    queue.append((crawl_url, depth + 1))
                    
        return discovered
    
    # ─────────────────────────────────────────────────────────────────────────
    
    def run(self):
        print(f"[Scanner] Starting scan: {self.url}", flush=True)
        
        # Authentication
        self._perform_authentication()
        
        try:
            response = self.session.get(
                self.url,
                allow_redirects=True,
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException as e:
            return {
                **self.results,
                "status": "error",
                "error": str(e),
            }
            
        headers = response.headers
        body = response.text
        soup = BeautifulSoup(body, "html.parser")
        
        # Crawl only non-trusted targets
        if self.is_trusted:
            self.discovered_urls = [self.url]
        else:
            self.discovered_urls = self._crawl()
            
        futures = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            
            if self.opts.get("scan_owasp", True):
                futures["owasp"] = executor.submit(
                    self._check_owasp,
                    response,
                    headers,
                    body,
                    soup,
                )
                
            if self.opts.get("scan_injection", True) and not self.is_trusted:
                futures["injection"] = executor.submit(
                    self._check_injection,
                    response,
                    soup,
                )
                
            if self.opts.get("scan_ports", True):
                futures["ports"] = executor.submit(self._scan_ports)
                
            if self.opts.get("scan_tech", True):
                futures["tech"] = executor.submit(
                    self._detect_tech,
                    headers,
                    body,
                )
                
            if self.opts.get("scan_ssl", True):
                futures["ssl"] = executor.submit(self._check_ssl)
                
            if self.opts.get("scan_dns", True):
                futures["dns"] = executor.submit(self._check_dns)
                
            futures["waf"] = executor.submit(
                self._detect_waf,
                headers,
                body,
            )
            
            futures["files"] = executor.submit(
                self._check_sensitive_files,
            )
            
            futures["methods"] = executor.submit(
                self._check_http_methods,
            )
            
            futures["cookies"] = executor.submit(
                self._check_cookies,
                response,
            )
            
            futures["cors"] = executor.submit(
                self._check_cors,
            )
            
            futures["redirect"] = executor.submit(
                self._check_open_redirect,
            )
            
            if self.opts.get("scan_threat_intel", True):
                futures["vt"] = executor.submit(
                    check_virustotal,
                    self.url,
                )
                
                futures["shodan"] = executor.submit(
                    check_shodan,
                    self.hostname,
                )
                
                futures["gsb"] = executor.submit(
                    check_google_safe_browsing,
                    self.url,
                )
                
                futures["hibp"] = executor.submit(
                    check_hibp_domain,
                    self.hostname,
                )
                
            # Wait for all tasks and surface exceptions
            for name, future in futures.items():
                try:
                    future.result()
                except Exception as e:
                    print(f"[{name}] {e}", flush=True)
                    
        # Collect threat intelligence
        threat_intel = {}
        
        for key in ("vt", "shodan", "gsb", "hibp"):
            if key in futures:
                try:
                    threat_intel[key] = futures[key].result()
                except Exception:
                    threat_intel[key] = None
                    
        self.results["threat_intel"] = threat_intel
        self.results["score"] = self._calc_risk_score()
        
        print(
            f"[Scanner] Finished scan: {self.url} "
            f"({len(self.results['vulnerabilities'])} findings, "
            f"score {self.results['score']})",
            flush=True,
        )
        
        return {
            **self.results,
            "status": "complete",
            "url": self.url,
        }
        
    # ─────────────────────────────────────────────────────────────────────────
    
    def _extract_injectable_params(self, target_url, page_soup): # Extract Injectable Parameters
        
        parsed = urllib.parse.urlparse(target_url)
        params = {}
        
        for key, values in urllib.parse.parse_qs(parsed.query).items(): # URL Query Parameters
            
            if key.lower() in SKIP_PARAMS:
                continue
            
            value = values[0] if values else DEFAULT_PARAM_VALUE
            
            if value.lower() in SKIP_PARAM_VALUES:
                continue
            
            params[key] = value
            
        for form in page_soup.find_all("form"): # Form Parameters
            
            for field in form.find_all(["input", "textarea", "select"]):
                
                name = (field.get("name") or "").strip()
                
                if not name:
                    continue
                
                if name.lower() in SKIP_PARAMS:
                    continue
                
                if field.has_attr("disabled"):
                    continue
                
                if field.has_attr("readonly"):
                    continue
                
                field_type = (field.get("type") or "text").lower()
                
                if field_type in {
                    "submit",
                    "button",
                    "image",
                    "reset",
                    "file",
                    "checkbox",
                    "radio",
                    "hidden",
                }:
                    continue
                
                # Handle <select>
                if field.name == "select":
                    option = field.find("option", selected=True)
                    
                    if option is None:
                        option = field.find("option")
                        
                    value = (
                        option.get("value", "").strip()
                        if option
                        else DEFAULT_PARAM_VALUE
                    )
                    
                else:
                    value = (
                        field.get("value", "").strip()
                        or DEFAULT_PARAM_VALUE
                    )
                    
                if value.lower() in SKIP_PARAM_VALUES:
                    continue
                
                # Preserve query parameter value if already present
                params.setdefault(name, value)
                
        return params
    
    # ─────────────────────────────────────────────────────────────────────────
    
    def _is_db_param(self, param_key, target_url): # Returns True if the parameter name or URL path suggests a database-backed endpoint
        
        param_name = (param_key or "").lower()
        
        if param_name in DB_PARAM_HINTS:
            return True
        
        url_path = urllib.parse.urlparse(target_url).path.lower()
        
        return any(
            hint in url_path
            for hint in DB_PATH_HINTS
        )
        
    # ─────────────────────────────────────────────────────────────────────────
    
    def _baseline_has_sql_error(self, response_body): # Returns True if the original page already contains SQL error messages
        
        body = response_body or ""
        
        return any(
            pattern.search(body)
            for pattern in SQL_ERROR_PATTERNS
        )
        
    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_xss_context(self, response_body, payload): # Returns True if the payload appears in an executable HTML context (script block, event handler, or javascript: URI)
        
        body_lower = response_body.lower()
        payload_lower = payload.lower()
        
        idx = body_lower.find(payload_lower)
        if idx == -1:
            return False
        
        # Reject HTML-encoded payloads
        segment = body_lower[idx: idx + len(payload_lower) + 10]
        
        if any(ent in segment for ent in (
            "&lt;",
            "&gt;",
            "&#",
            "&quot;",
            "&apos;",
            "&amp;"
        )):
            return False
        
        context_before = body_lower[max(0, idx - 300): idx]
        context_after = body_lower[
            idx: min(len(body_lower), idx + len(payload_lower) + 100)
        ]
        
        context = context_before + context_after
        
        # Inside <script>...</script>
        last_script_open = context_before.rfind("<script")
        last_script_close = context_before.rfind("</script>")
        
        if last_script_open != -1 and last_script_open > last_script_close:
            return True
        
        # Payload itself is a script tag
        if "<script>" in payload_lower and "</script>" in payload_lower:
            return True
        
        # Event handler attribute
        event_attrs = (
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "onfocus=",
            "onblur=",
            "oninput=",
            "onsubmit=",
            "onanimationstart=",
            "onpointerenter=",
            "onmouseenter=",
        )
        
        if any(attr in context for attr in event_attrs):
            return True
        
        # javascript: URI
        if "javascript:" in context:
            return True
        
        return False
    
    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_owasp(self, response, headers, body, soup):
        h = headers
        
        # Skip OWASP active checks on trusted domains
        if self.is_trusted:
            return
        
        baseline = response.text[:5000]
        
        # ── A01 — Broken Access Control ──────────────────────────────────────
        admin_paths = (
            "/admin",
            "/admin/users",
            "/dashboard",
            "/api/users",
            "/api/admin",
        )
        
        admin_keywords = (
            "admin dashboard",
            "administrator",
            "user management",
            "control panel",
            "role management",
            "site settings",
        )
        
        for path in admin_paths:
            admin_url = urllib.parse.urljoin(self.url, path)
            
            try:
                r = self.session.get(
                    admin_url,
                    allow_redirects=False,
                    timeout=DEFAULT_TIMEOUT,
                )
            except requests.RequestException:
                continue
            
            similarity = difflib.SequenceMatcher(
                None,
                baseline,
                r.text[:5000],
            ).ratio()
            
            body_lower = r.text.lower()
            
            if (
                r.status_code == 200
                and len(r.text) > 500
                and similarity < 0.70
                and any(keyword in body_lower for keyword in admin_keywords)
            ):
                self._add({
                    "id": "A01-BAC",
                    "owasp_id": "A01:2025",
                    "category": "owasp",
                    "name": "Broken Access Control",
                    "severity": "medium",
                    "confidence": "low",
                    "description": f"Potentially sensitive endpoint accessible without authentication: {path}",
                    "impact": "Unauthenticated users may be able to access privileged functionality.",
                    "recommendation": "Enforce server-side authorization on every protected endpoint.",
                    "evidence": (
                        f"URL: {admin_url}\n"
                        f"Method: GET\n"
                        f"Status: {r.status_code}\n"
                        f"Size: {len(r.text)} bytes"
                    ),
                    "cvss": "5.3",
                })
                break
            
        # ── IDOR (Insecure Direct Object Reference) ──────────────────────────
        if self.parsed.query:
            params = urllib.parse.parse_qs(self.parsed.query)
            
            for key, values in params.items():
                if not values or not values[0].isdigit():
                    continue
                
                original_id = values[0]
                modified_id = str(int(original_id) + 1)
                
                new_params = dict(params)
                new_params[key] = [modified_id]
                
                test_url = self.parsed._replace(
                    query=urllib.parse.urlencode(new_params, doseq=True)
                ).geturl()
                
                try:
                    r = self.session.get(
                        test_url,
                        timeout=DEFAULT_TIMEOUT,
                    )
                except requests.RequestException:
                    continue
                
                similarity = difflib.SequenceMatcher(
                    None,
                    baseline,
                    r.text[:5000],
                ).ratio()
                
                if (
                    r.status_code == 200
                    and len(r.text) > 500
                    and similarity < 0.40
                    and abs(len(r.text) - len(response.text)) > 100
                ):
                    self._add({
                        "id": "A01-IDOR",
                        "owasp_id": "A01:2025",
                        "category": "owasp",
                        "name": "Potential IDOR (Insecure Direct Object Reference)",
                        "severity": "medium",
                        "confidence": "low",
                        "description": f"Changing numeric parameter '{key}' returned a different valid resource.",
                        "impact": "May allow unauthorized access to another user's data.",
                        "recommendation": "Validate object ownership server-side and use unpredictable identifiers (UUIDs).",
                        "evidence": (
                            f"Parameter: {key}\n"
                            f"Original Value: {original_id}\n"
                            f"Modified Value: {modified_id}\n"
                            f"URL: {test_url}\n"
                            f"Status: {r.status_code}"
                        ),
                        "cvss": "5.8",
                    })
                    break
            
        # ── A02 — Cryptographic Failures ─────────────────────────────────────
        
        if (
            self.parsed.scheme == "http"
            and self.hostname not in ("localhost", "127.0.0.1", "::1")
        ):
            self._add({
                "id": "A02-HTTPS",
                "owasp_id": "A02:2025",
                "category": "owasp",
                "name": "No HTTPS - Cleartext Transmission",
                "severity": "critical",
                "confidence": "high",
                "description": "The application is served over unencrypted HTTP.",
                "impact": "Credentials, cookies and other sensitive traffic may be intercepted.",
                "recommendation": "Redirect all HTTP traffic to HTTPS and deploy a valid TLS certificate.",
                "evidence": (
                    f"URL: {self.url}\n"
                    f"Scheme: HTTP"
                ),
                "cvss": "7.5",
            })
            
        if self.parsed.scheme == "https":
            
            hsts = headers.get("Strict-Transport-Security", "").lower()
            
            if not hsts:
                
                self._add({
                    "id": "A02-HSTS",
                    "owasp_id": "A02:2025",
                    "category": "owasp",
                    "name": "HSTS Header Missing",
                    "severity": "low",
                    "confidence": "high",
                    "description": "HTTPS responses do not include the Strict-Transport-Security header.",
                    "impact": "Browsers may allow insecure HTTP connections before HTTPS is enforced.",
                    "recommendation": "Configure HSTS with max-age=31536000; includeSubDomains.",
                    "evidence": (
                        f"URL: {self.url}\n"
                        f"Header: Strict-Transport-Security (missing)"
                    ),
                    "cvss": "3.7",
                })
                
            elif "max-age=0" in hsts:
                
                self._add({
                    "id": "A02-HSTS-ZERO",
                    "owasp_id": "A02:2025",
                    "category": "owasp",
                    "name": "HSTS Disabled",
                    "severity": "low",
                    "confidence": "high",
                    "description": "The HSTS policy is effectively disabled (max-age=0).",
                    "impact": "Browsers will not enforce HTTPS-only communication.",
                    "recommendation": "Use a positive max-age such as 31536000.",
                    "evidence": (
                        f"Strict-Transport-Security: {hsts}"
                    ),
                    "cvss": "3.1",
                })
                
            else:
                
                try:
                    max_age = int(re.search(r"max-age=(\d+)", hsts).group(1))
                    
                    if 0 < max_age < 86400:
                        self._add({
                            "id": "A02-HSTS-WEAK",
                            "owasp_id": "A02:2025",
                            "category": "owasp",
                            "name": "Weak HSTS Configuration",
                            "severity": "info",
                            "confidence": "high",
                            "description": "The configured HSTS max-age is shorter than recommended.",
                            "impact": "Browsers may not retain HTTPS enforcement for long.",
                            "recommendation": "Use max-age=31536000 or longer.",
                            "evidence": (
                                f"Strict-Transport-Security: {hsts}"
                            ),
                            "cvss": "0.0",
                        })
                        
                    if "includesubdomains" not in hsts:
                        self._add({
                            "id": "A02-HSTS-SUBDOMAINS",
                            "owasp_id": "A02:2025",
                            "category": "owasp",
                            "name": "HSTS Does Not Cover Subdomains",
                            "severity": "info",
                            "confidence": "high",
                            "description": "The HSTS policy does not include the includeSubDomains directive.",
                            "impact": "Subdomains may still be accessed over HTTP.",
                            "recommendation": "Add the includeSubDomains directive if appropriate.",
                            "evidence": (
                                f"Strict-Transport-Security: {hsts}"
                            ),
                            "cvss": "0.0",
                        })
                        
                    if "preload" not in hsts:
                        self._add({
                            "id": "A02-HSTS-PRELOAD",
                            "owasp_id": "A02:2025",
                            "category": "owasp",
                            "name": "HSTS Preload Not Enabled",
                            "severity": "info",
                            "confidence": "high",
                            "description": "The HSTS preload directive is not present.",
                            "impact": "The domain cannot be included in browser preload lists.",
                            "recommendation": "Consider adding the preload directive after meeting browser preload requirements.",
                            "evidence": (
                                f"Strict-Transport-Security: {hsts}"
                            ),
                            "cvss": "0.0",
                        })
                        
                except (AttributeError, ValueError):
                    pass
                
        # ── A04 — Insecure Design (Login Rate Limiting) ──────────────────────
        if (
            not self.is_trusted
            and self.results.get("auth", {}).get("status") != "success"
        ):
            login_forms = soup.find_all(
                "form",
                action=lambda action: action
                and any(
                    keyword in str(action).lower()
                    for keyword in ("login", "signin", "auth")
                ),
            )
            
            if not login_forms:
                login_forms = soup.find_all("form")
                
            for form in login_forms[:2]:
                if not form.find("input", {"type": "password"}):
                    continue
                
                try:
                    action = urllib.parse.urljoin(
                        response.url,
                        form.get("action") or response.url,
                    )
                    
                    responses = [
                        self.session.post(
                            action,
                            data={
                                "username": "scanner_test",
                                "password": "wrong_password",
                            },
                            timeout=DEFAULT_TIMEOUT,
                            allow_redirects=False,
                        )
                        for _ in range(10)
                    ]
                    
                    last = responses[-1]
                    body_lower = last.text.lower()
                    
                    rate_limited = (
                        last.status_code == 429
                        or any(
                            marker in body_lower
                            for marker in (
                                "too many requests",
                                "rate limit",
                                "captcha",
                                "temporarily blocked",
                                "account locked",
                                "try again later",
                            )
                        )
                    )
                    
                    if not rate_limited:
                        self._add({
                            "id": "A04-RATE-LIMIT",
                            "owasp_id": "A04:2025",
                            "category": "owasp",
                            "name": "Login Form Lacks Rate Limiting",
                            "severity": "low",
                            "confidence": "medium",
                            "description": (
                                "Multiple failed login attempts were accepted "
                                "without visible throttling or lockout."
                            ),
                            "impact": (
                                "May allow brute-force or credential stuffing attacks."
                            ),
                            "recommendation": (
                                "Implement request throttling, account lockout, "
                                "CAPTCHA, or MFA."
                            ),
                            "evidence": (
                                f"10 consecutive failed login attempts to {action} "
                                "completed without rate limiting."
                            ),
                            "cvss": "3.7",
                        })
                        
                except requests.RequestException:
                    pass
                
                break
            
        # ── A05 — Security Misconfiguration (Security Headers) ──────────────────────
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        required_headers = {
            "content-security-policy": (
                "Content-Security-Policy",
                "medium",
                "5.3",
            ),
            "x-frame-options": (
                "X-Frame-Options",
                "low",
                "3.1",
            ),
            "x-content-type-options": (
                "X-Content-Type-Options",
                "low",
                "3.1",
            ),
        }
        
        optional_headers = {
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
            "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
            "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
        }
        
        missing_required = [
            (display, severity, cvss)
            for key, (display, severity, cvss) in required_headers.items()
            if key not in headers_lower
        ]
        
        missing_optional = [
            display
            for key, display in optional_headers.items()
            if key not in headers_lower
        ]
        
        if missing_required:
            
            severity = (
                "medium"
                if any(s == "medium" for _, s, _ in missing_required)
                else "low"
            )
            
            cvss = "5.3" if severity == "medium" else "3.1"
            
            evidence = (
                f"URL: {self.url}\n"
                "Missing Required Headers:\n"
                + "\n".join(f"- {name}" for name, _, _ in missing_required)
            )
            
            if missing_optional:
                evidence += (
                    "\n\nMissing Optional Headers:\n"
                    + "\n".join(f"- {name}" for name in missing_optional)
                )
                
            self._add({
                "id": "A05-HEADERS",
                "owasp_id": "A05:2025",
                "category": "owasp",
                "name": "Missing Security Headers",
                "severity": severity,
                "confidence": "high",
                "description": (
                    f"{len(missing_required)} required security header(s) "
                    "are missing from the HTTP response."
                ),
                "impact": (
                    "Missing security headers increase exposure to "
                    "cross-site scripting (XSS), clickjacking, "
                    "MIME-sniffing, and other browser-based attacks."
                ),
                "recommendation": (
                    "Configure the missing security headers at the web server "
                    "or application level. At minimum implement "
                    "Content-Security-Policy, X-Frame-Options, and "
                    "X-Content-Type-Options."
                ),
                "evidence": evidence,
                "cvss": cvss,
            })
            
        # ── A06 — Vulnerable and Outdated Components ───────────────────────────────
        
        js_libs = [
            (r"jquery[/-](\d+\.\d+\.?\d*)", "jQuery", "3.7.0"),
            (r"bootstrap[/-](\d+\.\d+\.?\d*)", "Bootstrap", "5.3.0"),
            (r"angular[/-](\d+\.\d+\.?\d*)", "Angular", "17.0.0"),
            (r"react[/-](\d+\.\d+\.?\d*)", "React", "18.0.0"),
            (r"vue[/-](\d+\.\d+\.?\d*)", "Vue.js", "3.3.0"),
        ]
        
        for pattern, library, minimum_version in js_libs:
            
            match = re.search(pattern, body, re.IGNORECASE)
            
            if not match:
                continue
            
            detected_version = match.group(1)
            
            try:
                if self._version_tuple(detected_version) >= self._version_tuple(minimum_version):
                    continue
            except Exception:
                continue
            
            self._add({
                "id": f"A06-{library.upper().replace('.', '').replace(' ', '')}",
                "owasp_id": "A06:2025",
                "category": "owasp",
                "name": f"Outdated Component — {library} v{detected_version}",
                "severity": "medium",
                "confidence": "high",
                "description": (
                    f"{library} version {detected_version} appears older than the "
                    f"recommended minimum version ({minimum_version})."
                ),
                "impact": (
                    "Outdated third-party components may contain publicly known "
                    "security vulnerabilities such as XSS, prototype pollution, "
                    "or other library-specific CVEs."
                ),
                "recommendation": (
                    f"Upgrade {library} to version {minimum_version} or a newer "
                    "supported release and remove vulnerable legacy versions."
                ),
                "evidence": (
                    f"URL: {self.url}\n"
                    f"Library: {library}\n"
                    f"Detected Version: {detected_version}\n"
                    f"Recommended Minimum Version: {minimum_version}"
                ),
                "cvss": "6.1",
            })
            
        # ── A07 — Authentication Failures (Rate Limiting) ─────────────────────
        
        if (
            not self.is_trusted
            and self.results.get("auth", {}).get("status") != "success"
        ):
            
            login_forms = soup.find_all(
                "form",
                action=lambda a: a and any(
                    x in str(a).lower()
                    for x in ("login", "signin", "auth")
                ),
            )
            
            if not login_forms:
                login_forms = soup.find_all("form")
                
            for form in login_forms[:2]:
                
                if not form.find("input", {"type": "password"}):
                    continue
                
                action = urllib.parse.urljoin(
                    self.url,
                    form.get("action") or self.url,
                )
                
                login_session = requests.Session()
                login_session.headers.update(self.session.headers)
                
                payload = {}
                
                for field in form.find_all("input"):
                    name = field.get("name")
                    if not name:
                        continue
                    
                    field_type = (field.get("type") or "text").lower()
                    
                    if field_type == "password":
                        payload[name] = "WrongPassword123!"
                        
                    elif field_type in ("text", "email"):
                        payload[name] = "scanner@example.com"
                        
                    elif field_type == "hidden":
                        payload[name] = field.get("value", "")
                        
                try:
                    
                    responses = []
                    
                    for _ in range(10):
                        responses.append(
                            login_session.post(
                                action,
                                data=payload,
                                timeout=DEFAULT_TIMEOUT,
                                allow_redirects=False,
                            )
                        )
                        
                    last = responses[-1]
                    body_lower = last.text.lower()
                    
                    rate_limited = (
                        last.status_code == 429
                        or any(
                            marker in body_lower
                            for marker in (
                                "too many requests",
                                "rate limit",
                                "captcha",
                                "temporarily blocked",
                                "locked",
                            )
                        )
                    )
                    
                    if not rate_limited:
                        self._add({
                            "id": "A07-RATELIMIT",
                            "owasp_id": "A07:2025",
                            "category": "owasp",
                            "name": "Login Endpoint Missing Rate Limiting",
                            "severity": "low",
                            "confidence": "medium",
                            "description": "Multiple rapid login attempts were accepted without throttling or account lockout.",
                            "impact": "May allow automated credential guessing and brute-force attacks.",
                            "recommendation": "Implement rate limiting, account lockout, CAPTCHA, or progressive delays.",
                            "evidence": (
                                f"URL: {action}\n"
                                f"Method: POST\n"
                                f"Attempts: 10\n"
                                f"Last Status: {last.status_code}"
                            ),
                            "cvss": "3.7",
                        })
                        
                except requests.RequestException:
                    pass
                
                break
            
        # ── A08 — Software and Data Integrity Failures (SRI) ───────────────────────
        
        external_scripts = []
        
        for script in soup.find_all("script", src=True):
            
            src = script["src"].strip().lower()
            
            if not any(cdn in src for cdn in SRI_CDN_HINTS):
                continue
            
            if script.has_attr("integrity"):
                continue
            
            external_scripts.append(script["src"])
            
        if external_scripts:
            
            preview = "\n".join(f"- {s}" for s in external_scripts[:5])
            
            if len(external_scripts) > 5:
                preview += f"\n...and {len(external_scripts) - 5} more"
                
            self._add({
                "id": "A08-SRI",
                "owasp_id": "A08:2025",
                "category": "owasp",
                "name": "Missing Subresource Integrity (SRI)",
                "severity": "medium",
                "confidence": "high",
                "description": (
                    f"{len(external_scripts)} externally hosted JavaScript "
                    "resource(s) are loaded without Subresource Integrity."
                ),
                "impact": (
                    "If a third-party CDN or hosted JavaScript resource is "
                    "compromised, malicious code may execute in users' browsers."
                ),
                "recommendation": (
                    "Use the integrity attribute together with "
                    "crossorigin='anonymous' for externally hosted JavaScript "
                    "resources."
                ),
                "evidence": (
                    f"URL: {self.url}\n\n"
                    "External scripts without SRI:\n"
                    f"{preview}"
                ),
                "cvss": "6.8",
            })
            
        # ── A09 — Security Logging & Monitoring Failures ─────────────────────
        
        debug_patterns = (
            "traceback (most recent call last)",
            "stack trace",
            "exception occurred",
            "nullpointerexception",
            "system.nullreferenceexception",
            "sql syntax",
            "warning:",
            "fatal error",
            "notice:",
            "debug=true",
            "werkzeug debugger",
            "__debugger__",
            "django version",
            "asp.net",
            "laravel",
            "symfony exception",
        )
        
        body_lower = body.lower()
        
        if any(pattern in body_lower for pattern in debug_patterns):
            self._add({
                "id": "A09-DEBUG",
                "owasp_id": "A09:2025",
                "category": "owasp",
                "name": "Debug Information Exposed",
                "severity": "medium",
                "confidence": "high",
                "description": (
                    "The application exposes debugging or exception details "
                    "to users."
                ),
                "impact": (
                    "Internal implementation details may aid attackers during "
                    "reconnaissance and exploitation."
                ),
                "recommendation": (
                    "Disable debug mode and replace detailed exceptions with "
                    "generic error pages."
                ),
                "evidence": "Application response contains debugging or exception information.",
                "cvss": "5.3",
            })
            
        # ── A10 — Server-Side Request Forgery (SSRF) ──────────────────────────
        
        if not self.is_trusted and self.parsed.query:
            
            params = urllib.parse.parse_qs(self.parsed.query)
            
            ssrf_hints = {
                "url", "uri", "dest", "destination",
                "redirect", "next", "return",
                "link", "src", "path",
                "fetch", "load", "image",
                "proxy", "callback", "feed"
            }
            
            suspected = []
            
            for key, values in params.items():
                
                key_lower = key.lower()
                
                if any(hint in key_lower for hint in ssrf_hints):
                    suspected.append(key)
                    continue
                
                for value in values:
                    value = value.lower()
                    
                    if (
                        value.startswith(("http://", "https://"))
                        or re.match(r"^\d{1,3}(\.\d{1,3}){3}", value)
                    ):
                        suspected.append(key)
                        break
                    
            if suspected:
                
                confidence = (
                    "medium"
                    if any(
                        any(v.lower().startswith(("http://", "https://"))
                            for v in params[p])
                        for p in suspected
                    )
                    else "low"
                )
                
                self._add({
                    "id": "A10-SSRF",
                    "owasp_id": "A10:2025",
                    "category": "owasp",
                    "name": "Potential Server-Side Request Forgery (SSRF)",
                    "severity": "info",
                    "confidence": confidence,
                    "description": (
                        "The application contains URL-like parameters that may "
                        "be used for server-side resource fetching."
                    ),
                    "impact": (
                        "If user-controlled URLs are fetched without validation, "
                        "an attacker could access internal services, cloud metadata, "
                        "or other protected resources."
                    ),
                    "recommendation": (
                        "Validate and whitelist allowed destinations. "
                        "Block internal IP ranges, localhost, and metadata endpoints."
                    ),
                    "evidence": (
                        f"Potential SSRF parameters: {', '.join(sorted(set(suspected)))}"
                    ),
                    "cvss": "0.0",
                })
                
    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_injection(self, response, soup): # A03 - Injection (SQL, XSS, SSTI, LFI, CSRF, XXE)
        
        if self.is_trusted:
            return
        
        targets = self.discovered_urls or [self.url]
        
        print(f"[Injection] {len(targets)} page(s) queued", flush=True)
        
        found = {
            "sqli_error": False,
            "sqli_time": False,
            "sqli_boolean": False,
            "xss_reflect": False,
            "xss_stored": False,
            "csrf": False,
            "ssti": False,
            "lfi": False,
            "xxe": False,
            "xxe_out": False,
            "xxe_in": False,
        }
        
        for index, target in enumerate(targets, start=1):
            
            print(
                f"[Injection] [{index}/{len(targets)}] {target}",
                flush=True,
            )
            
            parsed = urllib.parse.urlparse(target)
            
            path = parsed.path.lower()
            filename = path.rsplit("/", 1)[-1]
            extension = (
                f".{filename.rsplit('.', 1)[-1]}"
                if "." in filename
                else ""
            )
            
            if extension in SKIP_EXTENSIONS:
                continue
            
            try:
                response = self.session.get(
                    target,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                )
                
                if response.status_code >= 400:
                    continue
                
                content_type = response.headers.get(
                    "Content-Type",
                    "",
                ).lower()
                
                if "html" not in content_type:
                    continue
                
            except requests.RequestException:
                continue
            
            page_soup = BeautifulSoup(
                response.text,
                "html.parser",
            )
            
            baseline_text = response.text
            
            test_params = {
                key: value
                for key, value in self._extract_injectable_params(
                    target,
                    page_soup,
                ).items()
                if str(value).strip()
            }
            
            if not test_params:
                continue
            
            # ── SQL Injection — Error-Based ───────────────────────────────────
            
            if not found["sqli_error"]:
                
                if self._baseline_has_sql_error(baseline_text):
                    pass  # Page already exposes SQL errors
                
                else:
                    
                    db_params = [
                        key
                        for key in test_params
                        if self._is_db_param(key, target)
                    ]
                    
                    if db_params:
                        
                        for payload in SQL_ERROR_PAYLOADS:
                            
                            for param_key in db_params[:4]:
                                
                                new_params = dict(test_params)
                                new_params[param_key] = payload
                                
                                test_url = parsed._replace(
                                    query=urllib.parse.urlencode(new_params)
                                ).geturl()
                                
                                try:
                                    response = self.session.get(
                                        test_url,
                                        timeout=DEFAULT_TIMEOUT,
                                    )
                                    
                                except requests.RequestException:
                                    continue
                                
                                matched = None
                                
                                for pattern in SQL_ERROR_PATTERNS:
                                    match = re.search(
                                        pattern,
                                        response.text,
                                        re.IGNORECASE,
                                    )
                                    
                                    if (
                                        match
                                        and match.group(0).strip().lower()
                                        not in baseline_text.lower()
                                    ):
                                        matched = match.group(0).strip()
                                        break
                                    
                                if matched:
                                    
                                    self._add({
                                        "id": "SQL-ERROR",
                                        "category": "injection",
                                        "name": "SQL Injection — Error-Based",
                                        "severity": "high",
                                        "confidence": "high",
                                        "description": (
                                            "Database error messages were returned "
                                            "after SQL metacharacter injection."
                                        ),
                                        "impact": (
                                            "May allow database enumeration, "
                                            "authentication bypass, or data disclosure."
                                        ),
                                        "recommendation": (
                                            "Use parameterized queries, validate input, "
                                            "and never expose database errors."
                                        ),
                                        "evidence": (
                                            f"URL: {test_url}\n"
                                            f"Parameter: {param_key}\n"
                                            f"Payload: {payload}\n"
                                            f"Matched Error: {matched}"
                                        ),
                                        "cvss": "8.1",
                                    })
                                    
                                    found["sqli_error"] = True
                                    break
                            if found["sqli_error"]:
                                break
                                
            # ── SQL Injection — Boolean-Based ────────────────────────────────
            
            if not found["sqli_boolean"]:
                
                db_params = [
                    key
                    for key in test_params
                    if self._is_db_param(key, target)
                ]
                
                if db_params:
                    
                    for param_key in db_params[:4]:
                        
                        original_value = str(
                            test_params.get(param_key, "")
                        ).strip()
                        
                        if not original_value:
                            continue
                        
                        for true_payload, false_payload in SQL_BOOLEAN_PAYLOADS:
                            
                            true_params = dict(test_params)
                            false_params = dict(test_params)
                            
                            true_params[param_key] = (
                                original_value + true_payload
                            )
                            
                            false_params[param_key] = (
                                original_value + false_payload
                            )
                            
                            true_url = parsed._replace(
                                query=urllib.parse.urlencode(true_params)
                            ).geturl()
                            
                            false_url = parsed._replace(
                                query=urllib.parse.urlencode(false_params)
                            ).geturl()
                            
                            try:
                                
                                true_response = self.session.get(
                                    true_url,
                                    timeout=DEFAULT_TIMEOUT,
                                )
                                
                                false_response = self.session.get(
                                    false_url,
                                    timeout=DEFAULT_TIMEOUT,
                                )
                                
                            except requests.RequestException:
                                continue
                            
                            status_changed = (
                                true_response.status_code
                                != false_response.status_code
                            )
                            
                            length_delta = abs(
                                len(true_response.text)
                                - len(false_response.text)
                            )
                            
                            if status_changed or length_delta > 300:
                                
                                self._add({
                                    "id": "SQL-BOOLEAN",
                                    "category": "injection",
                                    "name": "Potential SQL Injection — Boolean-Based",
                                    "severity": "high",
                                    "confidence": "medium",
                                    "description": (
                                        "The application responded differently "
                                        "to logically true and false SQL conditions."
                                    ),
                                    "impact": (
                                        "May allow blind SQL injection and "
                                        "database extraction."
                                    ),
                                    "recommendation": (
                                        "Use parameterized queries and "
                                        "validate all user input."
                                    ),
                                    "evidence": (
                                        f"True URL: {true_url}\n"
                                        f"False URL: {false_url}\n"
                                        f"Parameter: {param_key}\n"
                                        f"Status Codes: "
                                        f"{true_response.status_code} / "
                                        f"{false_response.status_code}\n"
                                        f"Response Length Difference: "
                                        f"{length_delta} bytes"
                                    ),
                                    "cvss": "7.5",
                                })
                                
                                found["sqli_boolean"] = True
                                break
                            
                        if found["sqli_boolean"]:
                            break
                        
            # ── SQL Injection — Time-Based ────────────────────────────────────
            
            if not found['sqli_time']:
                
                db_params = [k for k in test_params if self._is_db_param(k, target)]
                
                if db_params:
                    
                    # Measure baseline response time
                    baseline_times = []
                    
                    for _ in range(3):
                        try:
                            start = t.perf_counter()
                            self.session.get(target, timeout=10)
                            baseline_times.append(t.perf_counter() - start)
                        except requests.RequestException:
                            pass
                        
                    if not baseline_times:
                        continue
                    
                    baseline_elapsed = sum(baseline_times) / len(baseline_times)
                    
                    for param_key in db_params[:4]:
                        
                        original_value = str(test_params.get(param_key, "")).strip()
                        
                        if not original_value:
                            continue
                        
                        for db, payload in SQL_TIME_PAYLOADS:
                            
                            new_params = dict(test_params)
                            new_params[param_key] = original_value + payload
                            
                            test_url = parsed._replace(
                                query=urllib.parse.urlencode(new_params)
                            ).geturl()
                            
                            try:
                                start = t.perf_counter()
                                self.session.get(test_url, timeout=12)
                                elapsed = t.perf_counter() - start
                                
                            except requests.RequestException:
                                continue
                            
                            # Require ~3 second delay over baseline
                            if elapsed >= baseline_elapsed + 2.8:
                                
                                self._add({
                                    'id': 'SQL-TIME',
                                    'category': 'injection',
                                    'name': f'Potential SQL Injection — Time-Based Blind ({db})',
                                    'severity': 'high',
                                    'confidence': 'medium',
                                    'description': 'Response time increased significantly after a database time-delay payload.',
                                    'impact': 'Blind SQL injection allowing database enumeration and extraction.',
                                    'recommendation': 'Use parameterized queries and validate all user input.',
                                    'evidence': (
                                        f'URL: {target} | '
                                        f'Param: `{param_key}` | '
                                        f'DB: {db} | '
                                        f'Payload: `{payload}` | '
                                        f'Response: {elapsed:.2f}s '
                                        f'(baseline: {baseline_elapsed:.2f}s)'
                                    ),
                                    'cvss': '7.5',
                                })
                                
                                found['sqli_time'] = True
                                break
                            
                        if found['sqli_time']:
                            break
                        
            # ── Reflected Cross-Site Scripting (XSS) ───────────────────────────────
            
            if not found["xss_reflect"] and test_params:
                
                for payload in XSS_PAYLOADS:
                    
                    if found["xss_reflect"]:
                        break
                    
                    for param_key in list(test_params)[:5]:
                        
                        if not param_key or param_key.lower() in SKIP_PARAMS:
                            continue
                        
                        new_params = dict(test_params)
                        new_params[param_key] = payload
                        
                        test_url = parsed._replace(
                            query=urllib.parse.urlencode(new_params)
                        ).geturl()
                        
                        try:
                            response = self.session.get(test_url, timeout=8)
                            
                            content_type = response.headers.get("content-type", "").lower()
                            
                            if (
                                "text/html" not in content_type
                                and "application/xhtml+xml" not in content_type
                            ):
                                continue
                            
                            response_body = response.text
                            response_lower = response_body.lower()
                            
                            payload_lower = payload.lower()
                            escaped_payload = html.escape(payload).lower()
                            
                            reflected_raw = payload_lower in response_lower
                            reflected_escaped = escaped_payload in response_lower
                            
                            if (
                                reflected_raw
                                and not reflected_escaped
                                and self._check_xss_context(response_body, payload)
                            ):
                                self._add({
                                    "id": "XSS-REFLECT",
                                    "category": "injection",
                                    "name": "Potential Reflected XSS",
                                    "severity": "medium",
                                    "confidence": "medium",
                                    "description": "Input reflected into an executable HTML context without sufficient output encoding.",
                                    "impact": "Attackers may execute arbitrary JavaScript in victims' browsers.",
                                    "recommendation": "Apply context-aware output encoding and Content Security Policy (CSP).",
                                    "evidence": (
                                        f"URL: {target} | "
                                        f"Param: `{param_key}` | "
                                        f"Payload: `{payload}`"
                                    ),
                                    "cvss": "5.3",
                                })
                                
                                found["xss_reflect"] = True
                                break
                            
                        except requests.RequestException:
                            continue
                        
            # ── Stored Cross-Site Scripting (XSS) ───────────────────────────────────
            
            if not found["xss_stored"]:
                
                xss_payload = XSS_PAYLOADS[0]
                
                for form in page_soup.find_all("form")[:5]:
                    
                    if found["xss_stored"]:
                        break
                    
                    if form.get("method", "").upper() not in ("POST", ""):
                        continue
                    
                    text_fields = []
                    all_fields = {}
                    
                    for inp in form.find_all(["input", "textarea"]):
                        
                        field_name = (inp.get("name") or "").strip()
                        
                        if not field_name:
                            continue
                        
                        input_type = (inp.get("type") or "text").lower()
                        
                        if input_type in (
                            "submit",
                            "button",
                            "image",
                            "reset",
                            "file",
                        ):
                            continue
                        
                        value = (inp.get("value") or "").strip()
                        
                        if any(token in field_name.lower() for token in ("token", "csrf", "nonce")):
                            all_fields[field_name] = value
                            
                        elif input_type == "hidden":
                            all_fields[field_name] = value
                            
                        elif field_name.lower() not in SKIP_PARAMS:
                            text_fields.append(field_name)
                            all_fields[field_name] = value
                            
                    if not text_fields:
                        continue
                    
                    action = urllib.parse.urljoin(
                        target,
                        form.get("action") or target
                    )
                    
                    post_data = dict(all_fields)
                    post_data[text_fields[0]] = (
                        post_data.get(text_fields[0], "") + xss_payload
                    )
                    
                    try:
                        response = self.session.post(
                            action,
                            data=post_data,
                            timeout=8,
                            allow_redirects=True,
                        )
                        
                        verify_response = self.session.get(
                            response.url,
                            timeout=8,
                        )
                        
                        content_type = verify_response.headers.get(
                            "content-type",
                            "",
                        ).lower()
                        
                        if (
                            "text/html" not in content_type
                            and "application/xhtml+xml" not in content_type
                        ):
                            continue
                        
                        verify_body = verify_response.text
                        verify_lower = verify_body.lower()
                        
                        payload_lower = xss_payload.lower()
                        escaped_payload = html.escape(xss_payload).lower()
                        
                        reflected_raw = payload_lower in verify_lower
                        reflected_escaped = escaped_payload in verify_lower
                        
                        if (
                            reflected_raw
                            and not reflected_escaped
                            and self._check_xss_context(verify_body, xss_payload)
                        ):
                            
                            self._add({
                                "id": "XSS-STORED",
                                "category": "injection",
                                "name": "Potential Stored XSS",
                                "severity": "medium",
                                "confidence": "medium",
                                "description": "User-supplied content was stored and later rendered in an executable HTML context without proper output encoding.",
                                "impact": "Persistent JavaScript execution affecting all users viewing the stored content.",
                                "recommendation": "Sanitize user input and apply context-aware output encoding before rendering stored data.",
                                "evidence": (
                                    f"URL: {target} | "
                                    f"Field: `{text_fields[0]}` | "
                                    f"Payload persisted after POST and was reflected on page revisit."
                                ),
                                "cvss": "5.4",
                            })
                            
                            found["xss_stored"] = True
                            
                    except requests.RequestException:
                        continue
                    
            # ── Cross-Site Request Forgery (CSRF) ───────────────────────────────────
            
            if not found["csrf"]:
                
                set_cookie = response.headers.get(
                    "Set-Cookie",
                    "",
                ).lower()
                
                has_samesite = "samesite=" in set_cookie
                
                for form in page_soup.find_all("form"):
                    
                    method = (form.get("method") or "GET").upper()
                    
                    if method not in ("POST", "PUT", "PATCH", "DELETE"):
                        continue
                    
                    hidden_fields = [
                        (field.get("name") or "").lower()
                        for field in form.find_all("input", {"type": "hidden"})
                        if field.get("name")
                    ]
                    
                    has_token = any(
                        token in field
                        for field in hidden_fields
                        for token in CSRF_TOKEN_NAMES
                    )
                    
                    if has_token or has_samesite:
                        continue
                    
                    action = urllib.parse.urljoin(
                        target,
                        form.get("action") or target,
                    )
                    
                    self._add({
                        "id": "CSRF-01",
                        "category": "injection",
                        "name": "Potential Missing CSRF Protection",
                        "severity": "info",
                        "confidence": "low",
                        "description": (
                            "State-changing form detected without an obvious CSRF token "
                            "or SameSite cookie protection."
                        ),
                        "impact": (
                            "Heuristic finding only. Manual verification is required to "
                            "confirm whether the endpoint is vulnerable to CSRF."
                        ),
                        "recommendation": (
                            "Implement anti-CSRF tokens, SameSite cookies, Origin/Referer "
                            "validation, and verify CSRF protection on all state-changing endpoints."
                        ),
                        "evidence": (
                            f"Action: {action}\n"
                            f"Method: {method}\n"
                            f"Hidden fields: "
                            f"{', '.join(hidden_fields) if hidden_fields else 'None'}"
                        ),
                        "cvss": "0.0",
                    })
                    
                    found["csrf"] = True
                    break
                
            # ── Server-Side Template Injection (SSTI) ───────────────────────────────
            
            if not found["ssti"] and test_params:
                
                try:
                    baseline_body = self.session.get(target, timeout=6).text
                    baseline_lower = baseline_body.lower()
                    
                except requests.RequestException:
                    baseline_body = ""
                    baseline_lower = ""
                    
                for payload, expected in SSTI_PAYLOADS:
                    
                    if found["ssti"]:
                        break
                    
                    for param_key in list(test_params)[:4]:
                        
                        if not param_key or param_key.lower() in SKIP_PARAMS:
                            continue
                        
                        new_params = dict(test_params)
                        new_params[param_key] = payload
                        
                        test_url = parsed._replace(
                            query=urllib.parse.urlencode(new_params)
                        ).geturl()
                        
                        try:
                            response = self.session.get(
                                test_url,
                                timeout=6,
                            )
                            
                            content_type = response.headers.get(
                                "content-type",
                                "",
                            ).lower()
                            
                            if (
                                "text/html" not in content_type
                                and "application/xhtml+xml" not in content_type
                            ):
                                continue
                            
                            response_body = response.text
                            response_lower = response_body.lower()
                            
                            if not re.search(
                                rf"\b{re.escape(expected)}\b",
                                response_lower,
                            ):
                                continue
                            
                            if payload.lower() in response_lower:
                                continue
                            
                            if re.search(
                                rf"\b{re.escape(expected)}\b",
                                baseline_lower,
                            ):
                                continue
                            
                            similarity = difflib.SequenceMatcher(
                                None,
                                baseline_lower,
                                response_lower,
                            ).ratio()
                            
                            if similarity > 0.98:
                                continue
                            
                            index = response_lower.find(expected)
                            
                            context = response_lower[
                                max(0, index - 100):
                                index + 100
                            ]
                            
                            if re.search(
                                r"(var|let|const|function|px|em|rem|#)\s*"
                                + re.escape(expected),
                                context,
                            ):
                                continue
                            
                            snippet = (
                                response_body[
                                    max(0, index - 40):
                                    index + 40
                                ]
                                if index != -1
                                else "N/A"
                            )
                            
                            self._add({
                                "id": "SSTI-01",
                                "category": "injection",
                                "name": "Potential Server-Side Template Injection",
                                "severity": "medium",
                                "confidence": "medium",
                                "description": "Template expression appears to have been evaluated server-side.",
                                "impact": "May allow server-side code execution or disclosure of sensitive data.",
                                "recommendation": "Never render untrusted input inside server-side templates. Use sandboxing and proper escaping.",
                                "evidence": (
                                    f"URL: {target}\n"
                                    f"Parameter: {param_key}\n"
                                    f"Payload: {payload}\n"
                                    f"Expected Output: {expected}\n"
                                    f"Response Snippet: {snippet}"
                                ),
                                "cvss": "6.5",
                            })
                            
                            found["ssti"] = True
                            break
                        
                        except requests.RequestException:
                            continue
                        
            # ── Local File Inclusion (LFI) ─────────────────────────────────────
            if not found['lfi'] and test_params:
                
                for param_key in list(test_params.keys())[:5]:
                    
                    if not param_key:
                        continue
                    
                    if param_key.lower() in SKIP_PARAMS:
                        continue
                    
                    if param_key.lower() not in FILE_PARAMS:
                        continue
                    
                    for payload in LFI_PAYLOADS:
                        
                        new_params = dict(test_params)
                        new_params[param_key] = payload
                        
                        test_url = parsed._replace(
                            query=urllib.parse.urlencode(new_params)
                        ).geturl()
                        
                        try:
                            r = self.session.get(test_url, timeout=8)
                            
                        except requests.RequestException:
                            continue
                        
                        body = r.text
                        
                        # Linux detection
                        passwd_matches = re.findall(
                            r'^(root|daemon|bin|nobody):[^:]*:\d+:\d+:',
                            body,
                            re.MULTILINE
                        )
                        
                        # Windows detection
                        windows_detected = (
                            "[extensions]" in body.lower() or
                            "for 16-bit app support" in body.lower()
                        )
                        
                        if len(passwd_matches) >= 3 or windows_detected:
                            
                            snippet = "\n".join(passwd_matches[:3])
                            
                            self._add({
                                'id': 'LFI-01',
                                'category': 'injection',
                                'name': 'Potential Local File Inclusion (LFI)',
                                'severity': 'critical',
                                'confidence': 'high',
                                'description':
                                    'A local system file appears to be readable through user-controlled input.',
                                'impact':
                                    'May expose sensitive files and could lead to remote code execution depending on the application.',
                                'recommendation':
                                    'Use strict allowlists for file names, canonicalize paths, and never concatenate user input into filesystem paths.',
                                'evidence': (
                                    f'URL: {target}\n'
                                    f'Parameter: {param_key}\n'
                                    f'Payload: {payload}\n'
                                    f'Matches:\n{snippet if snippet else "Windows file detected"}'
                                ),
                                'cvss': '9.1',
                            })
                            
                            found['lfi'] = True
                            break
                        
                    if found['lfi']:
                        break
                    
            # ── XML External Entity (XXE) ───────────────────────────────────────────────────
            
            page_ct = response.headers.get("content-type", "").lower()
            
            xml_form = any(
                form.get("enctype", "").lower() in (
                    "text/xml",
                    "application/xml",
                )
                for form in page_soup.find_all("form")
            )
            
            if (
                (
                    "application/xml" in page_ct or
                    "text/xml" in page_ct or
                    "application/soap+xml" in page_ct or
                    xml_form
                )
                and "XXE-01" not in self._vuln_ids
            ):
                
                self._add({
                    'id': 'XXE-01',
                    'category': 'injection',
                    'name': 'Potential XML External Entity (XXE)',
                    'severity': 'high',
                    'confidence': 'low',
                    'description':
                        'The application appears to accept XML input. External entity processing should be reviewed.',
                    'impact':
                        'If XML parsers are insecurely configured, XXE may allow file disclosure, SSRF, or denial of service.',
                    'recommendation':
                        'Disable external entity resolution and DTD processing. Prefer JSON where practical.',
                    'evidence': (
                        f'URL: {target}\n'
                        f'Content-Type: {page_ct}\n'
                        f'XML Form Detected: {"Yes" if xml_form else "No"}'
                    ),
                    'cvss': '8.2',
                })
                
    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_sensitive_files(self):
        if self._is_trusted_domain(self.url):
            return
        
        try:
            baseline = self.session.get(self.url, timeout=6)
            baseline_text = baseline.text[:10000]
        except requests.RequestException:
            return
        
        for path, name, severity in SENSITIVE_FILES:
            try:
                test_url = urllib.parse.urljoin(self.url, path)
                r = self.session.get(test_url, timeout=6, allow_redirects=False)
                
                if r.status_code != 200:
                    continue
                
                # Don't process very large files
                if len(r.content) > 1024 * 1024:   # 1 MB
                    continue
                
                body = r.text
                if len(body.strip()) < 10:
                    continue
                
                sim = difflib.SequenceMatcher(
                    None,
                    baseline_text,
                    body[:10000]
                ).ratio()
                
                # Likely custom error page
                if sim > 0.85:
                    continue
                
                ct = r.headers.get("Content-Type", "").lower()
                
                # robots.txt
                if path == "/robots.txt":
                    has_sensitive = any(
                        p in body.lower()
                        for p in ROBOTS_SENSITIVE_HINTS
                    )
                    
                    self._add({
                        'id': 'FILE-ROBOTS',
                        'category': 'exposure',
                        'name': 'Robots.txt Publicly Accessible',
                        'severity': 'info',
                        'confidence': 'high',
                        'description':
                            '`/robots.txt` is publicly accessible.',
                        'impact':
                            'May disclose internal paths.'
                            if has_sensitive
                            else 'No direct security impact.',
                        'recommendation':
                            'Avoid listing sensitive paths in robots.txt.',
                        'evidence': (
                            f'URL: {test_url}\n'
                            f'Method: GET\n'
                            f'Status: {r.status_code}\n'
                            f'Content-Type: {ct}\n'
                            f'Size: {len(body)} bytes'
                        ),
                        'cvss': '2.6' if has_sensitive else '0.0',
                    })
                    continue
                
                filename = path.lstrip("/")
                
                if filename not in FILE_SIGNATURES:
                    continue

                # Reject HTML pages for files that should not be HTML
                if (
                    "html" in ct
                    and filename != "robots.txt"
                ):
                    continue

                matched = next(
                    (
                        sig
                        for sig in FILE_SIGNATURES[filename]
                        if sig.lower() in body.lower()
                    ),
                    None
                )

                if not matched:
                    continue

                self._add({
                    'id': f'FILE-{path.replace("/", "").upper()}',
                    'category': 'exposure',
                    'name': f'Sensitive File Exposed: {name}',
                    'severity': severity,
                    'confidence': 'high',
                    'description':
                        f'`{path}` appears to contain sensitive information.',
                    'impact':
                        'Potential credential, configuration, or source-code disclosure.',
                    'recommendation':
                        f'Remove or restrict public access to `{path}`.',
                    'evidence': (
                        f'URL: {test_url}\n'
                        f'Method: GET\n'
                        f'Status: {r.status_code}\n'
                        f'Content-Type: {ct}\n'
                        f'Size: {len(body)} bytes\n'
                        f'Matched Signature: {matched}'
                    ),
                    'cvss': CVSS_BY_SEVERITY.get(severity, '0.0'),
                })

            except requests.RequestException:
                continue

    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_http_methods(self):
        dangerous = {'TRACE': 'high', 'CONNECT': 'medium', 'PUT': 'low',
                    'DELETE': 'low', 'PATCH': 'info'}
        cvss_map = {'high': '6.5', 'medium': '4.3', 'low': '2.6', 'info': '0.0'}
        try:
            opts = self.session.options(self.url, timeout=6, allow_redirects=False)
            allow = opts.headers.get('Allow', '').upper()
        except requests.RequestException:
            allow = ''
        try:
            baseline = self.session.get(self.url, timeout=6, allow_redirects=False)
        except requests.RequestException:
            return

        for method, severity in dangerous.items():
            try:
                if allow and method not in allow:
                    continue
                r = self.session.request(method, self.url, timeout=6, allow_redirects=False)
                if r.status_code == 200 and r.text and r.text != baseline.text:
                    self._add({
                        'id': f'METHOD-{method}', 'category': 'owasp', 'owasp_id': 'A05:2025',
                        'name': f'Potentially Dangerous HTTP Method Enabled: {method}',
                        'severity': severity, 'confidence': 'low',
                        'description': f'Server appears to accept {method} requests.',
                        'impact': 'Increased attack surface if method is not required.',
                        'recommendation': f'Disable {method} if not needed.',
                        'evidence': f'{method} {self.url} → HTTP {r.status_code}',
                        'cvss': cvss_map.get(severity, '0.0'),
                    })
            except requests.RequestException:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_cookies(self, resp):
        SESSION_KW = {'session', 'sess', 'auth', 'token', 'jwt', 'login',
                    'sid', 'ssid', 'access', 'csrf', 'identity'}
        LOW_RISK_KW = {'nid', '_ga', '_gid', '_gat', '1p_jar', 'preferences',
                    'consent', 'cookie_notice', 'gdpr'}

        for cookie in resp.cookies:
            if cookie.name.startswith(('__Secure-', '__Host-')):
                if not cookie.secure:
                    self._add({
                        'id': f'COOKIE-PREFIX-{cookie.name}', 'category': 'owasp',
                        'owasp_id': 'A07:2025',
                        'name': f'Malformed Secure-Prefix Cookie — {cookie.name}',
                        'severity': 'low', 'confidence': 'high',
                        'description': f'`{cookie.name}` uses a secure prefix but lacks the Secure attribute.',
                        'impact': 'Browsers may reject the cookie.',
                        'recommendation': 'Always set Secure on __Secure-/__Host- cookies.',
                        'evidence': f'Set-Cookie: {cookie.name}; Secure absent',
                        'cvss': '3.1',
                    })
                continue

            flags = (str(getattr(cookie, '_rest', {})) + str(cookie.__dict__)).lower()
            nl = cookie.name.lower()
            is_session = any(kw in nl for kw in SESSION_KW)
            is_low_risk = any(kw in nl for kw in LOW_RISK_KW)
            httponly = 'httponly' in flags
            samesite = 'samesite' in flags

            issues = []
            if not cookie.secure:
                issues.append('Missing Secure flag')
            if not samesite:
                issues.append('Missing SameSite')
            if is_session and not httponly:
                issues.append('Missing HttpOnly')

            if not issues:
                continue

            if is_session:
                sev = 'medium' if len(issues) >= 2 else 'low'
                cvss = '5.3' if sev == 'medium' else '3.1'
                impact = 'Session cookie exposure to interception or CSRF.'
            elif is_low_risk:
                sev = 'info'
                cvss = '0.0'
                impact = 'Limited impact for analytics/preference cookies.'
            else:
                sev = 'low'
                cvss = '2.6'
                impact = 'Non-session cookie missing security attributes.'

            self._add({
                'id': f'COOKIE-{cookie.name}', 'category': 'owasp', 'owasp_id': 'A07:2025',
                'name': f'Cookie Security Attributes Missing — {cookie.name}',
                'severity': sev, 'confidence': 'high',
                'description': f'`{cookie.name}` missing: {", ".join(issues)}.',
                'impact': impact,
                'recommendation': 'Apply Secure, SameSite, HttpOnly as appropriate.',
                'evidence': f'Set-Cookie: {cookie.name}; issues: {", ".join(issues)}',
                'cvss': cvss,
            })

    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_cors(self):
        try:
            r = self.session.get(self.url, headers={'Origin': 'https://evil.com'}, timeout=8)
            acao = r.headers.get('access-control-allow-origin', '')
            acac = r.headers.get('access-control-allow-credentials', '')
            if acao == '*':
                self._add({
                    'id': 'CORS-WILDCARD', 'category': 'injection',
                    'name': 'CORS Wildcard Origin',
                    'severity': 'medium', 'confidence': 'high',
                    'description': 'ACAO: * allows any origin to read responses.',
                    'impact': 'Cross-origin data leakage from public endpoints.',
                    'recommendation': 'Replace wildcard with specific trusted origins.',
                    'evidence': 'Access-Control-Allow-Origin: *',
                    'cvss': '5.3',
                })
            elif acao == 'https://evil.com':
                sev = 'critical' if acac.lower() == 'true' else 'high'
                self._add({
                    'id': 'CORS-REFLECT', 'category': 'injection',
                    'name': 'CORS Arbitrary Origin Reflection',
                    'severity': sev, 'confidence': 'high',
                    'description': 'Server reflects arbitrary Origin. Credentials may be included.',
                    'impact': 'Full cross-origin data theft.',
                    'recommendation': 'Validate Origin against a strict whitelist.',
                    'evidence': f'ACAO: {acao}, ACAC: {acac}',
                    'cvss': '9.0' if sev == 'critical' else '7.5',
                })
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_open_redirect(self):
        redirect_params = ['redirect', 'next', 'url', 'return', 'dest',
                            'destination', 'redir', 'target', 'goto', 'link']
        evil_url = 'https://evil.com'
        safe_patterns = ['sorry', 'interstitial', 'warning', 'blocked', 'safebrowsing', 'consent']

        for param in redirect_params:
            test_url = (self.url + ('?' if '?' not in self.url else '&') +
                        f'{param}={urllib.parse.quote(evil_url)}')
            try:
                r = self.session.get(test_url, timeout=6, allow_redirects=False)
                if r.status_code not in (301, 302, 303, 307, 308):
                    continue
                location = r.headers.get('location', '').lower()
                is_safe = any(p in location for p in safe_patterns)
                is_external = 'evil.com' in location
                if is_external:
                    if is_safe:
                        self._add({
                            'id': 'REDIRECT-SAFE', 'category': 'redirect',
                            'name': 'External Redirect Handled via Interstitial',
                            'severity': 'info', 'confidence': 'high',
                            'description': 'Redirect goes through a warning page — no direct open redirect.',
                            'impact': 'No confirmed open redirect.',
                            'recommendation': 'Continue using allowlists for redirect destinations.',
                            'evidence': f'?{param}={evil_url} → {r.status_code} Location: {location[:200]}',
                            'cvss': '0.0',
                        })
                    else:
                        self._add({
                            'id': 'REDIRECT-01', 'category': 'redirect',
                            'name': 'Potential Open Redirect',
                            'severity': 'medium', 'confidence': 'high',
                            'description': f'`{param}` redirects to arbitrary external domains.',
                            'impact': 'Phishing, credential theft via redirect abuse.',
                            'recommendation': 'Validate redirect targets against a strict allowlist.',
                            'evidence': f'?{param}={evil_url} → {r.status_code} Location: {location[:200]}',
                            'cvss': '6.1',
                        })
                        return
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_ssl(self):
        if not self.hostname:
            return
        ssl_data = check_ssl_details(self.hostname)
        self.results['ssl_info'] = ssl_data
        if ssl_data.get('expired'):
            self._add({
                'id': 'SSL-EXPIRED', 'category': 'owasp', 'owasp_id': 'A02:2025',
                'name': 'SSL Certificate Expired',
                'severity': 'critical', 'confidence': 'high',
                'description': 'TLS certificate has expired.',
                'impact': 'User warnings, loss of trust, possible MITM',
                'recommendation': "Renew immediately. Use Let's Encrypt.",
                'evidence': f'Certificate expired: {ssl_data.get("expires")}',
                'cvss': '7.5',
            })
        elif ssl_data.get('expiring_soon'):
            days = ssl_data.get('days_remaining', 0)
            sev = 'low' if days <= 7 else 'info'
            self._add({
                'id': 'SSL-EXPIRING', 'category': 'owasp', 'owasp_id': 'A02:2025',
                'name': 'SSL Certificate Expiring Soon',
                'severity': sev, 'confidence': 'high',
                'description': f'Certificate expires in {days} days.',
                'impact': 'Renewal required soon.',
                'recommendation': 'Ensure automatic renewal is configured.',
                'evidence': f'Days remaining: {days}',
                'cvss': '3.1' if sev == 'low' else '0.0',
            })
        if ssl_data.get('weak_cipher'):
            self._add({
                'id': 'SSL-WEAKCIP', 'category': 'owasp', 'owasp_id': 'A02:2025',
                'name': 'Weak SSL Cipher Suite',
                'severity': 'high', 'confidence': 'high',
                'description': f'Cipher {ssl_data.get("cipher")} ({ssl_data.get("bits")} bits).',
                'impact': 'Possible decryption of recorded traffic.',
                'recommendation': 'Use TLS 1.3 and AES-256-GCM cipher suites.',
                'evidence': f'Cipher: {ssl_data.get("cipher")} ({ssl_data.get("bits")} bits)',
                'cvss': '7.4',
            })

    # ─────────────────────────────────────────────────────────────────────────
    
    def _check_dns(self):
        dns_data = check_dns_security(self.hostname)
        self.results['dns_security'] = dns_data
        ext = tldextract.extract(self.hostname)
        root_domain = f'{ext.domain}.{ext.suffix}'
        has_mx = bool(dns_data.get('mx'))

        if not dns_data.get('spf'):
            self._add({
                'id': 'DNS-SPF', 'category': 'dns',
                'name': 'SPF Record Not Detected',
                'severity': 'low' if has_mx else 'info', 'confidence': 'high',
                'description': 'No SPF TXT record detected.',
                'impact': 'Email spoofing risk.' if has_mx else 'No MX records — limited impact.',
                'recommendation': 'Configure SPF for authorized mail servers.',
                'evidence': f'No SPF TXT record for {self.hostname}',
                'cvss': '3.1' if has_mx else '0.0',
            })
        if not dns_data.get('dmarc'):
            self._add({
                'id': 'DNS-DMARC', 'category': 'dns',
                'name': 'DMARC Record Not Detected',
                'severity': 'low' if has_mx else 'info', 'confidence': 'high',
                'description': 'No DMARC record detected.',
                'impact': 'Reduced email spoofing protection.' if has_mx else 'No MX — limited impact.',
                'recommendation': 'Configure a DMARC policy.',
                'evidence': f'No DMARC at _dmarc.{root_domain}',
                'cvss': '3.1' if has_mx else '0.0',
            })
        if not dns_data.get('dnssec'):
            self._add({
                'id': 'DNS-DNSSEC', 'category': 'dns',
                'name': 'DNSSEC Not Enabled',
                'severity': 'info', 'confidence': 'high',
                'description': 'No DNSSEC DS records detected.',
                'impact': 'DNS relies on traditional trust mechanisms.',
                'recommendation': 'Enable DNSSEC at your registrar.',
                'evidence': f'No DS records for {root_domain}',
                'cvss': '0.0',
            })

    # ─────────────────────────────────────────────────────────────────────────
    
    def _detect_waf(self, headers, body):
        h_str = str(headers).lower()
        b_str = body.lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(s.lower() in h_str or s.lower() in b_str for s in sigs):
                self.results['waf'] = waf_name
                return
        try:
            probe = self.session.get(
                self.url + "/?a=<script>alert(1)</script>&b='OR 1=1--", timeout=6)
            if probe.status_code in (403, 406, 429, 503):
                ph = str({k.lower(): v for k, v in probe.headers.items()})
                if 'cloudflare' in ph:
                    self.results['waf'] = 'Cloudflare'
                elif 'sucuri' in ph:
                    self.results['waf'] = 'Sucuri'
                else:
                    self.results['waf'] = f'Unknown WAF (HTTP {probe.status_code})'
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    
    def _scan_ports(self):
        try:
            ip = socket.gethostbyname(self.hostname)
        except Exception:
            return

        def probe(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                result = s.connect_ex((ip, port))
                s.close()
                state = 'open' if result == 0 else 'closed'
            except Exception:
                state = 'filtered'
            service, risk = PORT_META.get(port, ('Unknown', 'info'))
            return {'port': port, 'state': state, 'service': service,
                    'protocol': 'TCP', 'risk': risk if state == 'open' else 'info'}

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            results = list(ex.map(probe, COMMON_PORTS))

        self.results['ports'] = results
        for p in results:
            if p['state'] == 'open' and p['risk'] == 'critical':
                self._add({
                    'id': f'PORT-{p["port"]}', 'category': 'ports',
                    'name': f'Critical Service Exposed: {p["service"]} ({p["port"]})',
                    'severity': 'critical', 'confidence': 'high',
                    'description': f'Port {p["port"]} ({p["service"]}) accessible from internet.',
                    'impact': 'Direct exploitation of database/remote access services.',
                    'recommendation': f'Restrict port {p["port"]} to trusted IPs via firewall.',
                    'evidence': f'Port {p["port"]}/TCP OPEN — {p["service"]}',
                    'cvss': '9.0',
                })

    # ─────────────────────────────────────────────────────────────────────────
    
    def _detect_tech(self, headers, body):
        techs = []
        h = headers
        
        def add_tech(name, cat, ver=None):
            if not any(x['name'].lower() == name.lower() for x in techs):
                techs.append({'name': name, 'category': cat, 'version': ver})
                
        server = h.get('server', '')
        if server:
            parts = server.split('/')
            add_tech(parts[0].strip(), 'Web Server',
                    parts[1].split(' ')[0] if len(parts) > 1 else None)
            
        powered = h.get('x-powered-by', '')
        if powered:
            parts = powered.split('/')
            add_tech(parts[0].strip(), 'Language', parts[1] if len(parts) > 1 else None)
            
        patterns = [
            (r'wp-content|wp-includes|wp-json', 'WordPress', 'CMS', r'wordpress[\s/]+([\d.]+)'),
            (r'drupal\.org|drupal\.js', 'Drupal', 'CMS', r'Drupal ([\d.]+)'),
            (r'joomla', 'Joomla', 'CMS', r'Joomla[\s/]+([\d.]+)'),
            (r'shopify', 'Shopify', 'E-Commerce', None),
            (r'magento', 'Magento', 'E-Commerce', r'Magento[\s/]+([\d.]+)'),
            (r'laravel', 'Laravel', 'Framework', None),
            (r'django', 'Django', 'Framework', None),
            (r'rails', 'Ruby on Rails', 'Framework', None),
            (r'next\.js|__next', 'Next.js', 'Framework', r'next[\s/]+([\d.]+)'),
            (r'nuxt', 'Nuxt.js', 'Framework', None),
            (r'react|__react', 'React', 'JavaScript', r'react[\s@/]+([\d.]+)'),
            (r'vue\.js|data-v-', 'Vue.js', 'JavaScript', r'vue[\s@/]+([\d.]+)'),
            (r'angular', 'Angular', 'JavaScript', r'angular[\s@/]+([\d.]+)'),
            (r'jquery', 'jQuery', 'JavaScript', r'jquery[\s@/v]+([\d.]+)'),
            (r'bootstrap', 'Bootstrap', 'CSS Framework', r'bootstrap[\s@/]+([\d.]+)'),
            (r'tailwind', 'Tailwind CSS', 'CSS Framework', None),
            (r'cloudflare', 'Cloudflare', 'CDN', None),
            (r'google-analytics|gtag|ga\.js', 'Google Analytics', 'Analytics', None),
            (r'nginx', 'Nginx', 'Web Server', r'nginx/([\d.]+)'),
            (r'apache', 'Apache', 'Web Server', r'Apache/([\d.]+)'),
            (r'node\.js|nodejs', 'Node.js', 'Runtime', r'node/([\d.]+)'),
            (r'php', 'PHP', 'Language', r'PHP/([\d.]+)'),
        ]
        
        all_text = body + str(headers)
        for pattern, name, cat, ver_pat in patterns:
            if re.search(pattern, all_text, re.I):
                ver = None
                if ver_pat:
                    m = re.search(ver_pat, all_text, re.I)
                    if m:
                        ver = m.group(1)
                add_tech(name, cat, ver)
                
        if h.get('cf-ray'):
            add_tech('Cloudflare', 'CDN')
        if self.url.startswith('https://'):
            add_tech('TLS/SSL', 'Security')
            
        self.results['technologies'] = techs
        
        for tech in techs[:4]:
            if tech['version']:
                cve_data = check_nvd_cves(tech['name'], tech['version'])
                for cve in cve_data.get('cves', []):
                    if float(cve.get('cvss', 0)) >= 7.0:
                        self._add({
                            'id': f'CVE-{cve["id"]}', 'category': 'cve', 'owasp_id': 'A06:2025',
                            'name': f'{cve["id"]} — {tech["name"]} v{tech["version"]}',
                            'severity': 'critical' if float(cve.get('cvss', 0)) >= 9 else 'high',
                            'confidence': 'high',
                            'description': cve.get('description', ''),
                            'impact': 'Component-specific exploitation.',
                            'recommendation': f'Upgrade {tech["name"]} from v{tech["version"]}.',
                            'evidence': f'CVSS {cve.get("cvss")} — {cve.get("published")}',
                            'cvss': str(cve.get('cvss', '')),
                        })
                        
    # ─────────────────────────────────────────────────────────────────────────
    
    def _calc_risk_score(self):
        findings = {
            v['id']: v
            for v in self.results['vulnerabilities']
        }.values()
        
        raw = sum(
            SEVERITY_WEIGHTS.get(
                v.get('severity', 'info').lower(), 0
            ) *
            CONFIDENCE_WEIGHTS.get(
                v.get('confidence', 'medium').lower(), 0.6
            )
            for v in findings
        )
        
        return min(round(100 * (1 - math.exp(-raw / 100))), 100)
