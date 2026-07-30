#!/usr/bin/env python3
"""
Analysetool für 123-bibel.de Access-Logs mit ip-api.com Geolocation
Extrahiert Besucher-IPs aus Heroku Router Logs, bestimmt Geolocation, VPN und Mobile-Netze
Rate-Limiting: 45 Anfragen/Minute mit intelligenter Wartezeit und Retry-Logik
"""

import gzip
import json
import os
import re
import sys
import ipaddress
import time
import requests
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional


class RateLimitedGeolocation:
    """
    Verwaltet Geolocation mit ip-api.com API
    - Rate-Limiting: 45 requests/minute (ip-api.com kostenlos-Plan)
    - Intelligente Wartezeit: ~1,5 Sekunden zwischen Anfragen
    - Retry-Logik mit exponential backoff bei Rate-Limit-Fehlern (HTTP 429)
    - Caching für bereits abgefragte IPs
    """
    
    API_URL = "http://ip-api.com/json"
    REQUEST_DELAY = 1.0  # Genau 1 Sekunde pro Request
    MAX_RETRIES = 3
    INITIAL_BACKOFF = 2.0  # Sekunden
    
    # VPN-Provider IP-Ranges (lokale Fallbacks)
    VPN_RANGES = [
        ('199.244.87.0', '199.244.88.255', 'Mullvad VPN'),
        ('45.33.32.0', '45.33.63.255', 'Linode (VPN-möglich)'),
        ('185.0.0.0', '185.255.255.255', 'Unbekannter VPN'),
    ]
    
    # Bekannte Bots
    BOT_ASNS = {
        'AS15169': 'Google',      # Google-Bot
        'AS8075': 'Microsoft',    # Microsoft Azure/Bing
        'AS14061': 'DigitalOcean',
    }
    
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.last_request_time = 0.0
        self.requests_count = 0
        self.failed_ips = set()
    
    @staticmethod
    def is_in_range(ip_str: str, start: str, end: str) -> bool:
        """Prüft, ob IP in Range liegt"""
        try:
            ip = ipaddress.ip_address(ip_str)
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            return start_ip <= ip <= end_ip
        except ValueError:
            return False
    
    @staticmethod
    def detect_vpn(ip: str) -> Tuple[bool, Optional[str]]:
        """Erkennt VPN-Verbindungen"""
        for start, end, provider in RateLimitedGeolocation.VPN_RANGES:
            if RateLimitedGeolocation.is_in_range(ip, start, end):
                return True, provider
        return False, None
    
    def _wait_for_rate_limit(self):
        """Wartet konstant 1 Sekunde zwischen Requests"""
        elapsed = time.time() - self.last_request_time
        wait_time = self.REQUEST_DELAY - elapsed
        
        if wait_time > 0:
            time.sleep(wait_time)
    
    def _fetch_from_api(self, ip: str, retry_count: int = 0) -> Optional[Dict]:
        """
        Ruft ip-api.com ab mit Retry-Logik
        
        Args:
            ip: IP-Adresse zu geocodieren
            retry_count: Aktuelle Retry-Nummer (für exponential backoff)
        
        Returns:
            Dictionary mit Geolocation-Daten oder None bei Fehler
        """
        try:
            # Rate-Limiting vor der Anfrage
            self._wait_for_rate_limit()
            
            # API-Anfrage
            response = requests.get(
                f"{self.API_URL}/{ip}",
                params={'fields': 'status,country,city,isp,as,asn,mobile,proxy,query'},
                timeout=10
            )
            
            self.last_request_time = time.time()
            self.requests_count += 1
            
            # Status 429 = Rate Limit überschritten
            if response.status_code == 429:
                if retry_count < self.MAX_RETRIES:
                    backoff_time = self.INITIAL_BACKOFF * (2 ** retry_count)
                    sys.stderr.write(f"  ⚠️  {ip}: Rate-Limit! Retry {retry_count + 1}/{self.MAX_RETRIES}\n")
                    sys.stderr.flush()
                    time.sleep(backoff_time)
                    # Rekursiver Retry mit erhöhtem Counter
                    return self._fetch_from_api(ip, retry_count + 1)
                else:
                    sys.stderr.write(f"  ❌ {ip}: Maximale Retries überschritten\n")
                    sys.stderr.flush()
                    self.failed_ips.add(ip)
                    return None
            
            response.raise_for_status()
            data = response.json()
            
            # API-Fehler prüfen
            if data.get('status') == 'fail':
                sys.stderr.write(f"  ⚠️  {ip}: {data.get('message', 'Unbekannt')}\n")
                sys.stderr.flush()
                self.failed_ips.add(ip)
                return None
            
            return data
        
        except requests.exceptions.Timeout:
            sys.stderr.write(f"  ⏱️  {ip}: Timeout\n")
            sys.stderr.flush()
            self.failed_ips.add(ip)
            return None
        
        except requests.exceptions.ConnectionError:
            sys.stderr.write(f"  🔌 {ip}: Verbindungsfehler\n")
            sys.stderr.flush()
            self.failed_ips.add(ip)
            return None
        
        except Exception as e:
            sys.stderr.write(f"  ❌ {ip}: {str(e)[:50]}\n")
            sys.stderr.flush()
            self.failed_ips.add(ip)
            return None
    
    def get_info(self, ip: str) -> Dict:
        """
        Holt Geolocation-Informationen für eine IP
        - Cache prüfen
        - API aufrufen wenn nötig
        - Lokale Heuristiken anwenden (VPN-Ranges, etc.)
        """
        # Cache prüfen
        if ip in self.cache:
            return self.cache[ip].copy()
        
        # Private IPs ignorieren
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                result = {
                    'provider': 'Privat',
                    'country': 'N/A',
                    'city': 'Lokal',
                    'isp': 'Privates Netzwerk',
                    'asn': 'N/A',
                    'vpn': False,
                    'mobile': False,
                    'proxy': False,
                    'bot': False,
                }
                self.cache[ip] = result
                return result.copy()
        except ValueError:
            pass
        
        # API-Anfrage
        api_data = self._fetch_from_api(ip)
        
        # Fallback: Lokale Heuristiken
        is_vpn, vpn_provider = self.detect_vpn(ip)
        
        if api_data and api_data.get('status') == 'success':
            # Daten von API verwenden
            asn = api_data.get('asn', 'N/A')
            is_bot = any(bot_asn in asn for bot_asn in self.BOT_ASNS.keys()) if asn != 'N/A' else False
            
            result = {
                'provider': api_data.get('isp', 'Unbekannt'),
                'country': api_data.get('country', 'N/A'),
                'city': api_data.get('city', 'N/A'),
                'isp': api_data.get('isp', 'Unbekannt'),
                'asn': asn,
                'vpn': is_vpn or api_data.get('proxy', False),
                'mobile': api_data.get('mobile', False),
                'proxy': api_data.get('proxy', False),
                'bot': is_bot,
            }
        else:
            # Fallback bei API-Fehler oder private IP
            result = {
                'provider': vpn_provider or 'Unbekannt',
                'country': 'N/A',
                'city': 'N/A',
                'isp': 'N/A',
                'asn': 'N/A',
                'vpn': is_vpn,
                'mobile': False,
                'proxy': False,
                'bot': False,
            }
        
        self.cache[ip] = result
        return result.copy()


class AccessLogAnalyzer:
    """Hauptklasse zur Analyse der Access-Logs"""
    
    def __init__(self, log_dir: str = '.'):
        self.log_dir = log_dir
        self.requests: List[Dict] = []
        self.unique_ips: set = set()
        self.geo = RateLimitedGeolocation()
    
    def extract_requests_from_gz(self, gz_file: str) -> int:
        """Extrahiert HTTP-Requests aus einer gzip-Datei"""
        count = 0
        try:
            with gzip.open(gz_file, 'rt') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        logmsg = entry.get('logmsg', '')
                        
                        if 'heroku/router' in entry.get('syslog_appname', '') and 'method=' in logmsg:
                            parsed = self._parse_heroku_router_log(entry, logmsg)
                            if parsed:
                                self.requests.append(parsed)
                                self.unique_ips.add(parsed['client_ip'])
                                count += 1
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"Fehler beim Lesen von {gz_file}: {e}")
        
        return count
    
    def _parse_heroku_router_log(self, entry: Dict, logmsg: str) -> Optional[Dict]:
        """Parst eine Heroku Router Log-Zeile"""
        match = re.search(r'method=(\w+)\s+path="([^"]+)".*fwd="([^"]+)"', logmsg)
        if not match:
            return None
        
        method, path, client_ip = match.groups()
        timestamp = entry.get('syslog', {}).get('timestamp', '')
        
        status_match = re.search(r'status=(\d+)', logmsg)
        status_code = status_match.group(1) if status_match else 'N/A'
        
        return {
            'timestamp': timestamp,
            'date': timestamp.split('T')[0] if timestamp else 'N/A',
            'time': timestamp.split('T')[1][:8] if timestamp else 'N/A',
            'client_ip': client_ip,
            'method': method,
            'path': path,
            'status': status_code,
        }
    
    def analyze_all_logs(self) -> int:
        """Analysiert alle gzip-Dateien im Verzeichnis"""
        gz_files = sorted(Path(self.log_dir).glob('*.gz'))
        total = 0
        
        print(f"Analysiere {len(gz_files)} Log-Dateien...")
        for gz_file in gz_files:
            count = self.extract_requests_from_gz(str(gz_file))
            if count > 0:
                print(f"  ✓ {gz_file.name}: {count} Requests")
            total += count
        
        return total
    
    def enrich_with_geolocation(self):
        """Reichert alle Requests mit Geolocation-Daten an"""
        valid_ips = [ip for ip in self.unique_ips if ip != 'N/A']
        total_ips = len(valid_ips)
        
        print(f"\n Geocodiere {total_ips} einzigartige IPs...")
        print(f"   Delay: {RateLimitedGeolocation.REQUEST_DELAY}s pro Anfrage")
        print(f"   Geschätzte Zeit: ~{total_ips * RateLimitedGeolocation.REQUEST_DELAY:.0f} Sekunden ({total_ips * RateLimitedGeolocation.REQUEST_DELAY / 60:.1f} Minuten)\n")
        
        start_time = time.time()
        
        for i, ip in enumerate(sorted(valid_ips), 1):
            # Zeige IP und aktuellen Progress
            sys.stdout.write(f"[{i:>3}/{total_ips}] {ip:<18} ")
            sys.stdout.flush()
            
            geo_info = self.geo.get_info(ip)
            
            # Zeige kurze Info über die IP
            country = geo_info.get('country', 'N/A')
            provider = geo_info.get('provider', 'N/A')[:20]  # Kürze auf 20 Zeichen
            flags = []
            if geo_info.get('vpn'):
                flags.append('VPN')
            if geo_info.get('proxy'):
                flags.append('PROXY')
            if geo_info.get('mobile'):
                flags.append('MOB')
            if geo_info.get('bot'):
                flags.append('BOT')
            
            flag_str = ','.join(flags) if flags else '—'
            print(f"✓ {country:<6} {provider:<20} [{flag_str}]")
            
            # Alle Requests mit dieser IP updaten
            for req in self.requests:
                if req['client_ip'] == ip:
                    req.update(geo_info)
        
        elapsed = time.time() - start_time
        print(f"\n  Geocodierung abgeschlossen in {elapsed:.1f} Sekunden!")
        print(f"   {len(self.geo.cache)} IPs gecacht")
        print(f"   {self.geo.requests_count} API-Anfragen")
        if self.geo.failed_ips:
            print(f"    {len(self.geo.failed_ips)} IPs fehlgeschlagen: {', '.join(sorted(list(self.geo.failed_ips)[:5]))}...")
    
    def print_summary(self):
        """Gibt Zusammenfassung aus"""
        print("\n" + "="*100)
        print("ZUSAMMENFASSUNG")
        print("="*100)
        
        total_requests = len(self.requests)
        unique_ips = len(self.unique_ips)
        vpn_count = sum(1 for r in self.requests if r.get('vpn'))
        mobile_count = sum(1 for r in self.requests if r.get('mobile'))
        bot_count = sum(1 for r in self.requests if r.get('bot'))
        proxy_count = sum(1 for r in self.requests if r.get('proxy'))
        
        print(f"Gesamt Requests:      {total_requests}")
        print(f"Einzigartige IPs:     {unique_ips}")
        print(f"API-Anfragen:         {self.geo.requests_count}")
        print(f"Gecachte IPs:         {len(self.geo.cache)}")
        print(f"VPN-Verbindungen:     {vpn_count}")
        print(f"Mobile-Netze:         {mobile_count}")
        print(f"Proxy/Anonymisiert:   {proxy_count}")
        print(f"Bots/Crawler:         {bot_count}")
        
        # Länderstatistik
        countries = defaultdict(int)
        for r in self.requests:
            if not r.get('bot'):
                countries[r.get('country', 'N/A')] += 1
        
        print("\nLänder (ohne Bots):")
        for country, count in sorted(countries.items(), key=lambda x: -x[1]):
            print(f"   {country}: {count}")
    
    def print_detailed_table(self):
        """Druckt detaillierte Tabelle"""
        print("\n" + "="*180)
        print("DETAILLIERTE ZUGRIFF-LISTE")
        print("="*180)
        
        print(f"{'Datum/Zeit':<20} {'IP':<18} {'Land':<15} {'Stadt':<20} {'Provider':<25} {'Status':<8} {'Flags':<30}")
        print("-" * 180)
        
        for r in sorted(self.requests, key=lambda x: x['timestamp']):
            flags = []
            if r.get('vpn'):
                flags.append('VPN')
            if r.get('proxy'):
                flags.append('PROXY')
            if r.get('mobile'):
                flags.append('MOBILE')
            if r.get('bot'):
                flags.append('BOT')
            
            dt = f"{r['date']} {r['time']}"
            flags_str = ','.join(flags) if flags else '-'
            
            print(f"{dt:<20} {r['client_ip']:<18} {r.get('country', 'N/A'):<15} "
                  f"{r.get('city', 'N/A'):<20} {r.get('provider', 'N/A'):<25} "
                  f"{r['status']:<8} {flags_str:<30}")
    
    def export_csv(self, filename: str = 'access_log_analysis.csv'):
        """Exportiert in CSV"""
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp', 'client_ip', 'country', 'city', 'provider', 'asn',
                'status', 'method', 'path', 'vpn', 'proxy', 'mobile', 'bot'
            ])
            writer.writeheader()
            
            for r in sorted(self.requests, key=lambda x: x['timestamp']):
                writer.writerow({
                    'timestamp': r['timestamp'],
                    'client_ip': r['client_ip'],
                    'country': r.get('country', 'N/A'),
                    'city': r.get('city', 'N/A'),
                    'provider': r.get('provider', 'N/A'),
                    'asn': r.get('asn', 'N/A'),
                    'status': r['status'],
                    'method': r['method'],
                    'path': r['path'],
                    'vpn': r.get('vpn', False),
                    'proxy': r.get('proxy', False),
                    'mobile': r.get('mobile', False),
                    'bot': r.get('bot', False),
                })
        
        print(f"✓ CSV exportiert: {filename}")
    
    def export_html(self, filename: str = 'access-log-report.html'):
        """Exportiert in HTML"""
        countries = defaultdict(int)
        for r in self.requests:
            if not r.get('bot'):
                countries[r.get('country', 'N/A')] += 1
        
        total_requests = len(self.requests)
        unique_ips = len(self.unique_ips)
        vpn_count = sum(1 for r in self.requests if r.get('vpn'))
        mobile_count = sum(1 for r in self.requests if r.get('mobile'))
        bot_count = sum(1 for r in self.requests if r.get('bot'))
        proxy_count = sum(1 for r in self.requests if r.get('proxy'))
        
        html = f"""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>123-bibel.de - Zugriff-Analyse</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8f9fa;
            color: #2d3436;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border-radius: 4px;
            overflow: hidden;
        }}
        .header {{
            background: #f1f3f5;
            border-bottom: 1px solid #dee2e6;
            padding: 50px 40px;
            text-align: center;
        }}
        .header h1 {{ 
            font-size: 32px; 
            margin-bottom: 8px; 
            color: #1a1a1a;
            font-weight: 600;
            letter-spacing: -0.5px;
        }}
        .header p {{ 
            color: #666;
            font-size: 13px;
            font-weight: 400;
            opacity: 1;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 20px;
            margin-top: 35px;
        }}
        .stat-box {{
            background: white;
            padding: 24px;
            border-radius: 4px;
            text-align: center;
            border: 1px solid #e9ecef;
            transition: box-shadow 0.2s ease;
        }}
        .stat-box:hover {{
            box-shadow: 0 2px 6px rgba(0,0,0,0.05);
        }}
        .stat-number {{ 
            font-size: 32px; 
            font-weight: 700; 
            color: #1a1a1a;
            margin-bottom: 8px;
        }}
        .stat-label {{ 
            font-size: 12px; 
            margin: 0; 
            color: #c3a51d;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .section {{
            padding: 45px 40px;
            border-bottom: 1px solid #e9ecef;
        }}
        .section:last-child {{
            border-bottom: none;
        }}
        .section h2 {{ 
            color: #1a1a1a; 
            margin-bottom: 30px; 
            font-size: 18px;
            font-weight: 600;
            letter-spacing: -0.3px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            color: #2d3436;
        }}
        th {{
            background: #fafbfc;
            color: #1a1a1a;
            padding: 14px 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }}
        td {{ 
            padding: 12px;
            border-bottom: 1px solid #e9ecef;
            color: #555;
        }}
        tr:hover {{ 
            background: #fafbfc;
        }}
        tr.vpn {{ background: #f8f9ff; }}
        tr.vpn:hover {{ background: #f1f3ff; }}
        tr.mobile {{ background: #f8f9ff; }}
        tr.mobile:hover {{ background: #f1f3ff; }}
        tr.proxy {{ background: #f8f9ff; }}
        tr.proxy:hover {{ background: #f1f3ff; }}
        tr.bot {{ background: #fafbfc; }}
        tr.bot:hover {{ background: #f3f5f7; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            margin-right: 6px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}
        .badge-vpn {{ background: #e7e8ff; color: #5a5c9b; }}
        .badge-mobile {{ background: #e7e8ff; color: #5a5c9b; }}
        .badge-proxy {{ background: #e7e8ff; color: #5a5c9b; }}
        .badge-bot {{ background: #eeeff2; color: #777; }}
        .country-list {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
        }}
        .country-item {{
            padding: 14px;
            background: #fafbfc;
            border-left: 3px solid #efcc2b;
            border-radius: 3px;
            font-size: 13px;
        }}
        .country-item strong {{ 
            color: #1a1a1a;
            font-weight: 600;
        }}
        footer {{
            text-align: center;
            color: #666;
            font-size: 11px;
            margin-top: 0;
            padding: 25px 40px;
            background: #f8f9fa;
            border-top: 1px solid #e9ecef;
        }}
        footer p {{
            margin: 4px 0;
        }}
        code {{ 
            background: #f3f5f7; 
            padding: 2px 6px; 
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #555;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>123-bibel.de - Zugriff-Analyse</h1>
            <p>Geocodiert mit ip-api.com (Rate-Limited)</p>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">{total_requests}</div>
                    <div class="stat-label">Gesamt Requests</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{unique_ips}</div>
                    <div class="stat-label">Einzigartige IPs</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{vpn_count}</div>
                    <div class="stat-label">VPN</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{proxy_count}</div>
                    <div class="stat-label">Proxy</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{mobile_count}</div>
                    <div class="stat-label">Mobile</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{bot_count}</div>
                    <div class="stat-label">Bots</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Geografische Verteilung (ohne Bots)</h2>
            <div class="country-list">
"""
        
        for country, count in sorted(countries.items(), key=lambda x: -x[1]):
            html += f'                <div class="country-item"><strong>{country}</strong>: {count} Zugriff{"e" if count != 1 else ""}</div>\n'
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <h2>Detaillierte Zugriff-Liste</h2>
            <table>
                <tr>
                    <th>Datum/Uhrzeit</th>
                    <th>IP-Adresse</th>
                    <th>Land</th>
                    <th>Stadt</th>
                    <th>Provider</th>
                    <th>ASN</th>
                    <th>Status</th>
                    <th>Flags</th>
                </tr>
"""
        
        for r in sorted(self.requests, key=lambda x: x['timestamp']):
            classes = []
            if r.get('vpn'):
                classes.append('vpn')
            if r.get('proxy'):
                classes.append('proxy')
            if r.get('mobile'):
                classes.append('mobile')
            if r.get('bot'):
                classes.append('bot')
            
            class_str = f' class="{" ".join(classes)}"' if classes else ''
            
            flags = ''
            if r.get('vpn'):
                flags += '<span class="badge badge-vpn">VPN</span>'
            if r.get('proxy'):
                flags += '<span class="badge badge-proxy">PROXY</span>'
            if r.get('mobile'):
                flags += '<span class="badge badge-mobile">MOBILE</span>'
            if r.get('bot'):
                flags += '<span class="badge badge-bot">BOT</span>'
            
            dt = f"{r['date']} {r['time']}"
            html += f"""                <tr{class_str}>
                    <td>{dt}</td>
                    <td><code>{r['client_ip']}</code></td>
                    <td>{r.get('country', 'N/A')}</td>
                    <td>{r.get('city', 'N/A')}</td>
                    <td>{r.get('provider', 'N/A')}</td>
                    <td>{r.get('asn', 'N/A')}</td>
                    <td>{r['status']}</td>
                    <td>{flags}</td>
                </tr>
"""
        
        html += """
            </table>
        </div>
        
        <footer>
            <p>Geocodierung mit ip-api.com (kostenlos, 45 Requests/Minute)</p>
            <p>Generated mit analyze_access_logs.py - Rate-Limited mit intelligenter Retry-Logik</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✓ HTML-Report exportiert: {filename}")


def main():
    """Hauptfunktion"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Analysiert 123-bibel.de Access-Logs mit ip-api.com Geocodierung',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python3 analyze_access_logs.py -d ./logs/ --csv out.csv --html out.html
  python3 analyze_access_logs.py --directory ./logs/
        """
    )
    
    parser.add_argument('-d', '--directory', default='.', help='Verzeichnis mit Log-Dateien')
    parser.add_argument('--csv', default='access-log-analysis.csv', help='CSV-Datei exportieren')
    parser.add_argument('--html', default='access-log-report.html', help='HTML-Report exportieren')
    
    args = parser.parse_args()
    
    # Analyzer ausführen
    print("Starte Access-Log Analyse...\n")
    analyzer = AccessLogAnalyzer(args.directory)
    total = analyzer.analyze_all_logs()
    
    if total == 0:
        print("Keine HTTP-Requests gefunden")
        sys.exit(1)
    
    # Geocodierung
    analyzer.enrich_with_geolocation()
    
    # Ausgaben
    print()
    analyzer.print_summary()
    print()
    analyzer.print_detailed_table()
    
    # Exporte
    print()
    analyzer.export_csv(args.csv)
    analyzer.export_html(args.html)
    
    print("\nAnalyse abgeschlossen!")


if __name__ == '__main__':
    main()