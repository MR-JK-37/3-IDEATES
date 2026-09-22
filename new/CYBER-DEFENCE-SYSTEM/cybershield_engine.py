#!/usr/bin/env python3
"""
CYBERSHIELD PRO - Real-Time System Monitoring Engine
Core backend service that provides live monitoring data to the mobile app.
Monitors system processes, network traffic, file activity, and threat indicators.
"""

import os
import sys
import json
import time
import psutil
import socket
import hashlib
import struct
import logging
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Any
import threading
import subprocess
import re
from dataclasses import dataclass, asdict
from enum import Enum
import requests
from urllib.parse import urlparse
import base64
import hashlib as _hashlib
import os
import time as _time
import json as _json
from html import unescape

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('/tmp/cybershield.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class ThreatType(Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    SUSPICIOUS_NETWORK = "SUSPICIOUS_NETWORK"
    SUSPICIOUS_FILE = "SUSPICIOUS_FILE"
    SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"
    UNUSUAL_BEHAVIOR = "UNUSUAL_BEHAVIOR"


@dataclass
class Threat:
    """Represents a detected threat"""
    id: str
    type: str
    severity: str
    name: str
    description: str
    timestamp: str
    details: Dict[str, Any]
    
    def to_dict(self):
        return asdict(self)


@dataclass
class SystemMetrics:
    """Real-time system metrics"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    disk_percent: float
    process_count: int
    threat_count: int
    system_health_percent: float
    status: str


@dataclass
class NetworkConnection:
    """Active network connection"""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    status: str
    process_name: str
    process_id: int
    is_suspicious: bool = False
    threat_indicator: str = ""


class EntropyAnalyzer:
    """Analyze file entropy to detect packing/encryption (potential malware indicator)"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * (probability and __import__('math').log2(probability) or 0)
        
        return entropy
    
    @staticmethod
    def is_suspicious_entropy(entropy: float) -> Tuple[bool, str]:
        """
        Check if entropy indicates suspicious activity.
        Normal text: 4-5 bits/byte
        Compressed/encrypted: 7-8 bits/byte (potential malware indicator)
        """
        if entropy > 7.5:
            return True, "HIGH_ENTROPY_DETECTED (Possible packing/encryption)"
        elif entropy > 6.5:
            return True, "ELEVATED_ENTROPY (Suspicious compression)"
        return False, ""


class SignatureDetector:
    """Pattern matching for known malware signatures and suspicious behavior"""
    
    SUSPICIOUS_PATTERNS = [
        (b'GetProcAddress', "API hooking attempt"),
        (b'CreateRemoteThread', "Process injection"),
        (b'VirtualAllocEx', "Kernel-level access"),
        (b'SetWindowsHookEx', "Hook injection"),
        (b'shellcode', "Shellcode detected"),
        (b'WinExec', "Direct process execution"),
        (b'RegOpenKeyEx', "Registry manipulation"),
    ]
    
    SUSPICIOUS_EXTENSIONS = {
        '.scr': 'Screen saver (executable)',
        '.vbs': 'VBScript (automation)',
        '.js': 'JavaScript (automation)',
        '.bat': 'Batch script',
        '.cmd': 'Command script',
        '.exe': 'Executable',
        '.dll': 'Dynamic library',
        '.sys': 'System driver',
    }
    
    @staticmethod
    def check_signatures(file_path: str) -> Tuple[bool, List[str]]:
        """Check file for known malware signatures"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(100000)  # Read first 100KB
            
            detected = []
            for pattern, description in SignatureDetector.SUSPICIOUS_PATTERNS:
                if pattern in content:
                    detected.append(description)
            
            return len(detected) > 0, detected
        except Exception as e:
            logger.debug(f"Signature check failed for {file_path}: {e}")
            return False, []
    
    @staticmethod
    def is_suspicious_extension(file_path: str) -> Tuple[bool, str]:
        """Check if file extension is suspicious"""
        ext = Path(file_path).suffix.lower()
        if ext in SignatureDetector.SUSPICIOUS_EXTENSIONS:
            return True, SignatureDetector.SUSPICIOUS_EXTENSIONS[ext]
        return False, ""


class FileScanner:
    """Real-time file scanning engine"""
    
    SYSTEM_DIRS = {'/sys', '/proc', '/dev', '/run', '/boot', '/root', '/var/log'}
    
    def __init__(self):
        self.scanned_files = {}
        self.threats = []
        # Lightweight file event queue to support real-time detection
        self._event_queue = deque()
        self._lock = threading.Lock()

    def handle_new_file(self, file_path: str):
        """Called by filesystem watcher when a new/modified file appears"""
        try:
            tl, indicators = self.scan_file(file_path)
            if tl != ThreatLevel.SAFE:
                threat = Threat(
                    id=hashlib.md5(file_path.encode()).hexdigest()[:8],
                    type=ThreatType.SUSPICIOUS_FILE.value,
                    severity=tl.value,
                    name=os.path.basename(file_path),
                    description=f"Realtime file event: {', '.join(indicators)}",
                    timestamp=datetime.now().isoformat(),
                    details={'path': file_path, 'indicators': indicators}
                )
                with self._lock:
                    self.threats.append(threat)
                return threat
        except Exception as e:
            logger.debug(f"Error handling new file {file_path}: {e}")
        return None
    
    def scan_file(self, file_path: str) -> Tuple[ThreatLevel, List[str]]:
        """Scan a single file for threats"""
        try:
            if not os.path.exists(file_path):
                return ThreatLevel.SAFE, []
            
            # Check if path is in system directories
            for sys_dir in self.SYSTEM_DIRS:
                if file_path.startswith(sys_dir):
                    return ThreatLevel.SAFE, []
            
            threat_indicators = []
            
            # Check extension
            is_suspicious, ext_reason = SignatureDetector.is_suspicious_extension(file_path)
            if is_suspicious:
                threat_indicators.append(f"Extension risk: {ext_reason}")
            
            # Check file size (suspicious if > 50MB for scripts)
            try:
                size = os.path.getsize(file_path)
                if size > 50 * 1024 * 1024:
                    threat_indicators.append(f"Unusually large file: {size / (1024*1024):.1f}MB")
            except:
                pass
            
            # Check entropy
            try:
                with open(file_path, 'rb') as f:
                    sample = f.read(10000)
                entropy = EntropyAnalyzer.calculate_entropy(sample)
                is_suspicious_entropy, entropy_reason = EntropyAnalyzer.is_suspicious_entropy(entropy)
                if is_suspicious_entropy:
                    threat_indicators.append(entropy_reason)
            except:
                pass
            
            # Check signatures
            has_signatures, signatures = SignatureDetector.check_signatures(file_path)
            if has_signatures:
                threat_indicators.extend(signatures)
            
            # YARA matches
            yara_matches = []
            try:
                if hasattr(self, '_owner') and getattr(self, '_owner', None) and getattr(self._owner, 'yara_rules', None):
                    for comp in self._owner.yara_rules:
                        try:
                            matches = comp.match(filepath=file_path)
                            for m in matches:
                                yara_matches.append(m.rule)
                        except Exception:
                            pass
            except Exception:
                pass

            # Behavior indicators (strings)
            behavior_hits = []
            try:
                with open(file_path, 'rb') as f:
                    raw = f.read(500000)
                try:
                    s = raw.decode('utf-8', errors='ignore').lower()
                except Exception:
                    s = ''

                suspicious_strings = ['powershell', 'invoke-expression', 'base64', 'frombase64string', 'eval(', 'exec(', 'socket', 'createconnection', 'wget', 'curl', 'system(', 'subprocess', 'execve', 'CreateProcess']
                for ss in suspicious_strings:
                    if ss in s:
                        behavior_hits.append(ss)
                        threat_indicators.append(f"Suspicious string: {ss}")
            except Exception:
                pass

            # Determine threat level using combined scoring
            intel = None
            try:
                # compute file hash for intel lookup
                h = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        h.update(chunk)
                sha256 = h.hexdigest()
                intel = None
                try:
                    intel = getattr(self, '_owner').threat_intel.lookup_hash(sha256)
                except Exception:
                    intel = None
            except Exception:
                sha256 = ''

            intel_score = (intel.get('score') if intel else 0) if intel else 0
            signatures_count = 1 if has_signatures else 0
            entropy_val = entropy if 'entropy' in locals() else 0.0
            behavior_score = min(len(behavior_hits) * 30, 100)
            yara_list = yara_matches

            overall = self._owner._compute_risk_score(signatures=signatures_count, entropy=entropy_val, yara_matches=yara_list, intel_score=int(intel_score), behavior_score=behavior_score)

            # Attach indicators from intel
            if intel and intel.get('verdict'):
                threat_indicators.append(f"Intel verdict: {intel.get('verdict')}")

            if overall >= 70:
                return ThreatLevel.CRITICAL, threat_indicators + yara_matches
            elif overall >= 30:
                return ThreatLevel.WARNING, threat_indicators + yara_matches
            elif overall > 0:
                return ThreatLevel.SUSPICIOUS, threat_indicators + yara_matches

            return ThreatLevel.SAFE, []
        
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
            return ThreatLevel.SAFE, []
    
    def scan_directory(self, path: str, limit: int = 100) -> List[Threat]:
        """Scan directory for threats (limited to avoid performance impact)"""
        threats = []
        scanned = 0
        
        try:
            for root, dirs, files in os.walk(path):
                if scanned >= limit:
                    break
                
                # Skip hidden and system directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if scanned >= limit:
                        break
                    
                    file_path = os.path.join(root, file)
                    threat_level, indicators = self.scan_file(file_path)
                    
                    if threat_level != ThreatLevel.SAFE:
                        threat = Threat(
                            id=hashlib.md5(file_path.encode()).hexdigest()[:8],
                            type=ThreatType.SUSPICIOUS_FILE.value,
                            severity=threat_level.value,
                            name=os.path.basename(file_path),
                            description=f"File scan detected: {', '.join(indicators)}",
                            timestamp=datetime.now().isoformat(),
                            details={'path': file_path, 'indicators': indicators}
                        )
                        threats.append(threat)
                    
                    scanned += 1
        except Exception as e:
            logger.debug(f"Error scanning directory {path}: {e}")
        
        return threats


class URLScanner:
    """Real-time URL analysis"""
    
    PHISHING_INDICATORS = [
        'login', 'signin', 'password', 'verify', 'confirm',
        'update', 'urgent', 'action', 'security', 'account',
    ]
    
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf',  # Free TLDs often used by attackers
        '.xyz', '.top', '.click', '.download',  # Generic dangerous TLDs
    ]
    
    @staticmethod
    def analyze_url(url: str) -> Tuple[ThreatLevel, List[str]]:
        """Analyze URL for malicious/phishing indicators"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            indicators = []
            
            # Check for suspicious TLD
            for tld in URLScanner.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    indicators.append(f"Suspicious TLD detected: {tld}")
            
            # Check for phishing indicators in path/query
            for indicator in URLScanner.PHISHING_INDICATORS:
                if indicator in path or indicator in parsed.query:
                    indicators.append(f"Phishing indicator: {indicator}")
            
            # Check for homograph attacks (unicode similar characters)
            if any(ord(c) > 127 for c in domain):
                indicators.append("Internationalized domain detected (homograph risk)")
            
            # Check for IP address instead of domain
            try:
                socket.inet_aton(domain)
                indicators.append("Direct IP address used (suspicious)")
            except socket.error:
                pass

            # Perform a lightweight HTTP(S) fetch to detect redirects, TLS, and page content indicators
            try:
                # Prefer HEAD first to avoid large downloads, but follow redirects to final URL
                resp = requests.head(url, allow_redirects=True, timeout=5)
                final_url = resp.url
                status = resp.status_code
                if resp.history and len(resp.history) > 2:
                    indicators.append(f"Redirect chain length {len(resp.history)}")

                # If HEAD yields HTML or unknown, fetch shallow GET to inspect content for login/password forms
                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' in content_type or content_type == '':
                    try:
                        getr = requests.get(url, allow_redirects=True, timeout=6)
                        page = getr.text.lower()
                        # Look for login/password fields or common phishing keywords
                        if any(k in page for k in ['name="password"', 'id="password"', 'input type="password"', 'form action="/login', 'form id="login']):
                            indicators.append('Page contains password/login form (possible credential harvesting)')
                        if 'paypal' in page and domain not in ('paypal.com', 'www.paypal.com'):
                            indicators.append('High similarity to paypal.com content')
                    except Exception:
                        pass

                # TLS certificate validation / hostname mismatch hints (best-effort)
                try:
                    parsed_final = urlparse(final_url)
                    if parsed_final.netloc and parsed_final.netloc != domain:
                        indicators.append(f'Final host differs from original: {parsed_final.netloc}')
                except Exception:
                    pass
            except Exception:
                # Network fetch failed; record as informational but not definitive
                indicators.append('Network fetch failed or timed out')
            
            # Determine threat level
            if len(indicators) >= 2:
                return ThreatLevel.WARNING, indicators
            elif len(indicators) >= 1:
                return ThreatLevel.SUSPICIOUS, indicators
            
            return ThreatLevel.SAFE, []
        
        except Exception as e:
            logger.debug(f"Error analyzing URL {url}: {e}")
            return ThreatLevel.SAFE, []


class NetworkMonitor:
    """Real-time network traffic and connection monitoring"""
    
    SUSPICIOUS_PORTS = {
        135: "RPC (WinRM)",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
        4444: "Metasploit",
        6666: "IRC",
        8888: "Proxy/Tunnel",
    }
    
    SUSPICIOUS_IPS = [
        '127.0.0.1',  # Localhost (unusual for external connections)
        '0.0.0.0',
        '255.255.255.255',
    ]
    
    def __init__(self):
        self.connection_history = deque(maxlen=1000)
        self.blocked_ips = set()
        # track repeated connection attempts: (ip,port) -> deque[timestamps]
        self._attempts = defaultdict(lambda: deque(maxlen=100))
        self._last_io = None
    
    def get_active_connections(self) -> List[NetworkConnection]:
        """Get current active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Get process info
                    process = psutil.Process(conn.pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "UNKNOWN"
                    conn.pid = 0
                
                remote_ip = conn.raddr[0] if conn.raddr else ""
                remote_port = conn.raddr[1] if conn.raddr else 0
                local_ip = conn.laddr[0] if conn.laddr else ""
                local_port = conn.laddr[1] if conn.laddr else 0
                
                # Determine if suspicious
                is_suspicious = False
                threat_indicator = ""
                
                if remote_port in self.SUSPICIOUS_PORTS:
                    is_suspicious = True
                    threat_indicator = f"Suspicious port: {self.SUSPICIOUS_PORTS[remote_port]}"
                
                if remote_ip and remote_ip not in self.SUSPICIOUS_IPS and not remote_ip.startswith('192.168'):
                    # Connection to external IP
                    pass
                
                # Get protocol name safely
                protocol = str(conn.type).split('.')[-1] if hasattr(conn.type, 'split') else str(conn.type)
                
                nc = NetworkConnection(
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    protocol=protocol,
                    status=str(conn.status),
                    process_name=process_name,
                    process_id=conn.pid,
                    is_suspicious=is_suspicious,
                    threat_indicator=threat_indicator
                )
                
                connections.append(nc)
                self.connection_history.append(asdict(nc))
                # track attempts
                if nc.remote_ip:
                    key = (nc.remote_ip, nc.remote_port)
                    self._attempts[key].append(time.time())
                    # if >5 attempts within 10s -> suspicious
                    times = list(self._attempts[key])
                    if len(times) >= 5 and times[-1] - times[0] < 10:
                        nc.is_suspicious = True
                        nc.threat_indicator = (nc.threat_indicator + ' | Repeated connection attempts') if nc.threat_indicator else 'Repeated connection attempts'
        
        except Exception as e:
            logger.error(f"Error getting connections: {e}")
        
        return connections

    def connection_attempts_summary(self):
        """Return small summary of repeated attempts"""
        out = []
        for (ip, port), dq in self._attempts.items():
            if len(dq) >= 3:
                out.append({'remote': f'{ip}:{port}', 'count': len(dq), 'last': dq[-1]})
        return out
    
    def analyze_network_logs(self) -> List[Threat]:
        """Analyze network activity for threats"""
        threats = []
        connections = self.get_active_connections()
        
        suspicious_conns = [c for c in connections if c.is_suspicious]
        
        for conn in suspicious_conns:
            threat = Threat(
                id=hashlib.md5(f"{conn.remote_ip}:{conn.remote_port}".encode()).hexdigest()[:8],
                type=ThreatType.SUSPICIOUS_NETWORK.value,
                severity=ThreatLevel.WARNING.value,
                name=f"{conn.remote_ip}:{conn.remote_port}",
                description=f"Process '{conn.process_name}' established connection to {conn.remote_ip}:{conn.remote_port}. {conn.threat_indicator}",
                timestamp=datetime.now().isoformat(),
                details={
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'process_name': conn.process_name,
                    'threat_indicator': conn.threat_indicator
                }
            )
            threats.append(threat)
        
        return threats


class ProcessMonitor:
    """Real-time process monitoring"""
    
    SUSPICIOUS_PROCESS_NAMES = [
        'svchost', 'lsass', 'smss', 'wininit',  # Windows suspicious
        'xmrig', 'cryptonight', 'minerd',  # Mining
        'curl', 'wget', 'nc', 'ncat',  # Command-line downloaders
    ]
    
    def __init__(self):
        self.known_processes = {}
    
    def get_suspicious_processes(self) -> List[Threat]:
        """Detect suspicious processes"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline']):
                try:
                    name = proc.info['name'].lower()
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower() if proc.info['cmdline'] else ""
                    
                    # Check for suspicious names
                    for suspicious in self.SUSPICIOUS_PROCESS_NAMES:
                        if suspicious in name:
                            threat = Threat(
                                id=hashlib.md5(f"{proc.info['pid']}:{name}".encode()).hexdigest()[:8],
                                type=ThreatType.SUSPICIOUS_PROCESS.value,
                                severity=ThreatLevel.SUSPICIOUS.value,
                                name=name,
                                description=f"Process '{name}' detected. This process name is associated with suspicious activity.",
                                timestamp=datetime.now().isoformat(),
                                details={'pid': proc.info['pid'], 'cmdline': cmdline}
                            )
                            threats.append(threat)
                            break
                    
                    # Check for suspicious command-line patterns
                    if any(pattern in cmdline for pattern in ['-c', '|', '&&', ';', 'whoami', 'ipconfig']):
                        if 'powershell' in name or 'cmd' in name:
                            threat = Threat(
                                id=hashlib.md5(f"{proc.info['pid']}:cmdline".encode()).hexdigest()[:8],
                                type=ThreatType.UNUSUAL_BEHAVIOR.value,
                                severity=ThreatLevel.SUSPICIOUS.value,
                                name=f"{name} with suspicious args",
                                description=f"Process '{name}' executing command with suspicious pattern: {cmdline[:100]}",
                                timestamp=datetime.now().isoformat(),
                                details={'pid': proc.info['pid'], 'cmdline': cmdline}
                            )
                            threats.append(threat)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            logger.error(f"Error monitoring processes: {e}")
        
        return threats


class SystemMonitor:
    """Aggregate system health and metrics"""
    
    def __init__(self):
        self.threat_history = deque(maxlen=100)
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get current system health metrics"""
        cpu = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Calculate system health percentage
        # Lower usage = healthier system
        health = 100 - (cpu * 0.3 + memory.percent * 0.4 + disk.percent * 0.3)
        health = max(0, min(100, health))
        
        # Determine status
        if health > 80:
            status = "SAFE"
        elif health > 60:
            status = "WARNING"
        else:
            status = "CRITICAL"
        
        return SystemMetrics(
            timestamp=datetime.now().isoformat(),
            cpu_percent=cpu,
            memory_percent=memory.percent,
            memory_mb=memory.used / (1024 * 1024),
            disk_percent=disk.percent,
            process_count=len(psutil.pids()),
            threat_count=len(self.threat_history),
            system_health_percent=health,
            status=status
        )


class CybershieldEngine:
    """Main monitoring engine that coordinates all scanners"""
    
    def __init__(self):
        self.file_scanner = FileScanner()
        self.url_scanner = URLScanner()
        self.network_monitor = NetworkMonitor()
        self.process_monitor = ProcessMonitor()
        self.system_monitor = SystemMonitor()
        self.threat_intel = ThreatIntel()
        # Start a simple filesystem watcher to catch new files in Downloads and /tmp
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            class _FSEventHandler(FileSystemEventHandler):
                def __init__(self, engine_ref):
                    self.engine_ref = engine_ref

                def on_created(self, event):
                    if not event.is_directory:
                        self.engine_ref.file_scanner.handle_new_file(event.src_path)

                def on_modified(self, event):
                    if not event.is_directory:
                        self.engine_ref.file_scanner.handle_new_file(event.src_path)

            self._observer = Observer()
            downloads = os.path.join(str(Path.home()), 'Downloads')
            watch_paths = [p for p in [downloads, '/tmp'] if os.path.exists(p)]
            for p in watch_paths:
                self._observer.schedule(_FSEventHandler(self), p, recursive=False)
            if watch_paths:
                self._observer.daemon = True
                self._observer.start()
                logger.info(f"File watcher started on: {watch_paths}")
        except Exception as e:
            logger.info(f"File watcher not available or failed to start: {e}")
        
        self.all_threats = deque(maxlen=500)
        self.last_scan_time = {}
        self.monitoring_active = True
        # Preload YARA rules (if available)
        try:
            import yara
            # search multiple rule directories: ./rules and ./ml/yara_rules
            self.yara_rules = None
            compiled = []
            base = os.path.dirname(__file__)
            candidates = [os.path.join(base, 'rules'), os.path.join(base, 'ml', 'yara_rules')]
            for rules_dir in candidates:
                try:
                    if os.path.isdir(rules_dir):
                        for fn in os.listdir(rules_dir):
                            if fn.endswith('.yar') or fn.endswith('.yara') or fn.endswith('.rules'):
                                path = os.path.join(rules_dir, fn)
                                try:
                                    compiled.append(yara.compile(filepath=path))
                                    logger.info(f"Compiled YARA rule: {path}")
                                except Exception as e:
                                    logger.debug(f"Failed to compile YARA {path}: {e}")
                except Exception:
                    pass
            self.yara_rules = compiled if compiled else None
            logger.info(f"YARA rules loaded: {len(compiled)}")
        except Exception as e:
            self.yara_rules = None
            logger.info(f"YARA not available or no rules compiled: {e}")

        # bind owner reference so FileScanner can call back for intel and scoring
        try:
            self.file_scanner._owner = self
        except Exception:
            pass

        # small cache for recent intel lookups
        self._intel_cache = {}

    def _compute_risk_score(self, signatures: int, entropy: float, yara_matches: List[str], intel_score: int, behavior_score: int) -> int:
        """Combine multiple signals into unified 0-100 score.

        weights:
          signatures: 25
          entropy: 20 (normalized)
          yara: 30
          intel: 40
          behavior: 30
        Scores normalized and capped.
        """
        score = 0.0
        score += min(signatures * 10, 25)
        # entropy: map 0-8 -> 0-20
        score += min(max((entropy - 4.0) / 4.0 * 20.0, 0), 20)
        # yara: each match 10 points up to 30
        score += min(len(yara_matches) * 10, 30)
        # intel_score expected 0-100 -> weight 40%
        score += min(intel_score * 0.4, 40)
        # behavior score 0-100 -> weight 30% scaled to 30
        score += min(behavior_score * 0.3, 30)

        return int(min(100, score))
    
    def run_threat_detection(self) -> Dict[str, Any]:
        """Execute all threat detection modules"""
        threats = []
        
        # Network analysis
        threats.extend(self.network_monitor.analyze_network_logs())
        
        # Process analysis
        threats.extend(self.process_monitor.get_suspicious_processes())
        
        # File scanning (limited directories for performance)
        home_dir = str(Path.home())
        threats.extend(self.file_scanner.scan_directory(os.path.join(home_dir, 'Downloads'), limit=50))
        threats.extend(self.file_scanner.scan_directory('/tmp', limit=30))
        
        # Update threat history
        for threat in threats:
            self.all_threats.append(threat)
        
        # Get system metrics
        metrics = self.system_monitor.get_system_metrics()
        self.system_monitor.threat_history = self.all_threats
        
        return {
            'timestamp': datetime.now().isoformat(),
            'threats': [t.to_dict() for t in list(self.all_threats)[-50:]],  # Last 50 threats
            'threat_count': len(self.all_threats),
            'metrics': asdict(metrics),
            'connections': [asdict(c) for c in self.network_monitor.get_active_connections() if c.is_suspicious][:20],
            'connection_attempts': self.network_monitor.connection_attempts_summary(),
        }
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """Analyze a specific URL"""
        threat_level, indicators = self.url_scanner.analyze_url(url)
        # check threat intel reputation for url / domain
        rep = self.threat_intel.lookup_url(url)
        indicators.extend(rep.get('indicators', []))
        score = self._compute_risk_score(signatures=0, entropy=0.0, yara_matches=[], intel_score=rep.get('score',0), behavior_score=0)

        if score >= 70:
            severity = ThreatLevel.CRITICAL.value
        elif score >= 30:
            severity = ThreatLevel.WARNING.value
        elif score > 0 or threat_level != ThreatLevel.SAFE:
            severity = ThreatLevel.SUSPICIOUS.value
        else:
            severity = ThreatLevel.SAFE.value

        if severity != ThreatLevel.SAFE.value:
            threat = Threat(
                id=hashlib.md5(url.encode()).hexdigest()[:8],
                type=ThreatType.PHISHING.value if 'phishing' in str(indicators).lower() else ThreatType.SUSPICIOUS_NETWORK.value,
                severity=severity,
                name=url,
                description=f"URL analysis: {', '.join(indicators)}",
                timestamp=datetime.now().isoformat(),
                details={'url': url, 'indicators': indicators, 'intel': rep}
            )
            self.all_threats.append(threat)

        return {
            'url': url,
            'threat_level': severity,
            'indicators': indicators,
            'intel': rep,
            'risk_score': score,
            'is_safe': severity == ThreatLevel.SAFE.value,
        }


class ThreatIntel:
    """Lightweight threat intelligence integration.

    Supports VirusTotal if `VT_API_KEY` environment variable is set.
    Otherwise uses passive checks (DNS, RDAP, iptoasn) and local caches.
    """
    def __init__(self):
        self.vt_key = os.environ.get('VT_API_KEY')
        self.session = requests.Session()
        self._recent = deque(maxlen=200)

    def lookup_hash(self, sha256: str) -> Dict[str, Any]:
        """Lookup file hash reputation. Returns dict with score, verdict, indicators."""
        if not sha256:
            return {'score': 0, 'verdict': 'UNKNOWN', 'indicators': []}
        if self.vt_key:
            try:
                headers = {'x-apikey': self.vt_key}
                url = f'https://www.virustotal.com/api/v3/files/{sha256}'
                r = self.session.get(url, headers=headers, timeout=6)
                if r.status_code == 200:
                    data = r.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    score = min(100, malicious * 10 + suspicious * 5)
                    verdict = 'MALICIOUS' if malicious > 0 else ('SUSPICIOUS' if suspicious > 0 else 'CLEAN')
                    out = {'score': score, 'verdict': verdict, 'indicators': [f"vt_malicious:{malicious}", f"vt_suspicious:{suspicious}"]}
                    self._recent.append(out)
                    return out
            except Exception:
                pass

        # Fallback: unknown hash -> neutral
        out = {'score': 0, 'verdict': 'UNKNOWN', 'indicators': []}
        self._recent.append(out)
        return out

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not ip:
            return {'score': 0, 'verdict': 'UNKNOWN', 'indicators': []}
        # Check cache
        if ip in getattr(self, '_cache', {}):
            return self._cache[ip]
        out = {'score': 0, 'verdict': 'CLEAN', 'indicators': []}
        try:
            # use iptoasn to get ASN info
            r = self.session.get(f'https://api.iptoasn.com/v1/as/ip/{ip}', timeout=5)
            if r.status_code == 200:
                j = r.json()
                asn = j.get('as_number')
                desc = j.get('as_description')
                out['indicators'].append(f'AS{asn}:{desc}')
                # heuristic: if ASN contains 'hosting' or 'bulletproof', increase score
                if desc and any(k in desc.lower() for k in ['hosting', 'vpn', 'proxy', 'botnet']):
                    out['score'] += 50
                    out['verdict'] = 'SUSPICIOUS'
        except Exception:
            pass
        # save
        try:
            self._cache = getattr(self, '_cache', {})
            self._cache[ip] = out
        except Exception:
            pass
        self._recent.append(out)
        return out

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Lookup URL reputation: domain/IP checks and VirusTotal if available."""
        try:
            p = urlparse(url)
            host = p.netloc.split(':')[0]
            out = {'score': 0, 'verdict': 'UNKNOWN', 'indicators': []}
            # VirusTotal URL lookup
            if self.vt_key:
                try:
                    headers = {'x-apikey': self.vt_key}
                    vt_url = 'https://www.virustotal.com/api/v3/urls'
                    resp = self.session.post(vt_url, data={'url': url}, headers=headers, timeout=6)
                    if resp.status_code in (200, 201):
                        resj = resp.json()
                        # follow to analysis
                        analysis_id = resj.get('data', {}).get('id')
                        if analysis_id:
                            stat = self.session.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers, timeout=6)
                            if stat.status_code == 200:
                                aj = stat.json()
                                # best-effort parse
                                out['score'] = 50
                                out['verdict'] = 'SUSPICIOUS'
                                out['indicators'].append('vt_url_analysis')
                except Exception:
                    pass

            # Fallback DNS resolve
            try:
                r = self.session.get(f'https://dns.google/resolve?name={host}&type=A', timeout=4)
                if r.status_code == 200:
                    j = r.json()
                    if 'Answer' in j:
                        answers = j['Answer']
                        for a in answers:
                            if 'data' in a:
                                ip = a['data']
                                iprep = self.lookup_ip(ip)
                                if iprep.get('score', 0) > 0:
                                    out['score'] = max(out.get('score',0), iprep.get('score'))
                                    out['indicators'].extend(iprep.get('indicators', []))
            except Exception:
                pass

            self._recent.append(out)
            return out
        except Exception:
            return {'score': 0, 'verdict': 'UNKNOWN', 'indicators': []}

    def recent_summary(self):
        return {'recent_count': len(self._recent)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get current system status"""
        metrics = self.system_monitor.get_system_metrics()
        return {
            'status': metrics.status,
            'health_percent': metrics.system_health_percent,
            'threats_detected': len(self.all_threats),
            'active_connections': len(self.network_monitor.get_active_connections()),
            'timestamp': metrics.timestamp,
            'intel_summary': self.threat_intel.recent_summary() if hasattr(self, 'threat_intel') else {}
        }


if __name__ == '__main__':
    engine = CybershieldEngine()
    print("CYBERSHIELD PRO - Monitoring Engine Started")
    print(json.dumps(engine.run_threat_detection(), indent=2))
