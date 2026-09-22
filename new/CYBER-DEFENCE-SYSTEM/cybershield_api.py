#!/usr/bin/env python3
"""
CYBERSHIELD PRO - REST API Server
Exposes real-time monitoring data to the mobile app.
All data is live, no mock/fake data.
"""

from flask import Flask, jsonify, request, Response
import os
import hashlib as _hashlib
import os
from flask_cors import CORS
import threading
import time
import logging
import json
from datetime import datetime, timedelta
from cybershield_engine import CybershieldEngine, Threat

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global engine instance
engine = CybershieldEngine()
last_full_scan = time.time()
SCAN_INTERVAL = 10  # Run full threat detection every 10 seconds


def background_monitor():
    """Background thread that continuously monitors system"""
    global last_full_scan
    
    while engine.monitoring_active:
        try:
            current_time = time.time()
            
            # Run full threat detection periodically
            if current_time - last_full_scan >= SCAN_INTERVAL:
                engine.run_threat_detection()
                last_full_scan = current_time
            
            time.sleep(1)
        
        except Exception as e:
            logger.error(f"Error in background monitor: {e}")
            time.sleep(5)


# Start background monitoring thread
monitor_thread = threading.Thread(target=background_monitor, daemon=True)
monitor_thread.start()


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current system status and threat summary"""
    try:
        status = engine.get_status()
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get all detected threats"""
    try:
        limit = request.args.get('limit', 50, type=int)
        threats = [t.to_dict() for t in list(engine.all_threats)[-limit:]]
        return jsonify({'threats': threats, 'count': len(threats)}), 200
    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Get system metrics (CPU, memory, disk, health %)"""
    try:
        metrics = engine.system_monitor.get_system_metrics()
        return jsonify({
            'timestamp': metrics.timestamp,
            'cpu_percent': metrics.cpu_percent,
            'memory_percent': metrics.memory_percent,
            'memory_mb': metrics.memory_mb,
            'disk_percent': metrics.disk_percent,
            'process_count': metrics.process_count,
            'threat_count': metrics.threat_count,
            'system_health_percent': metrics.system_health_percent,
            'status': metrics.status,
        }), 200
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network', methods=['GET'])
def get_network_connections():
    """Get active network connections"""
    try:
        connections = engine.network_monitor.get_active_connections()
        suspicious = [c for c in connections if c.is_suspicious]
        
        return jsonify({
            'active': len(connections),
            'suspicious': len(suspicious),
            'connections': [
                {
                    'local_ip': c.local_ip,
                    'local_port': c.local_port,
                    'remote_ip': c.remote_ip,
                    'remote_port': c.remote_port,
                    'protocol': c.protocol,
                    'process_name': c.process_name,
                    'is_suspicious': c.is_suspicious,
                    'threat_indicator': c.threat_indicator,
                }
                for c in connections[-50:]  # Last 50 connections
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error getting network: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    """Scan a URL for threats"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL required'}), 400
        
        result = engine.scan_url(url)
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    """Scan a file for threats"""
    try:
        logger.info(f"Scan-file request: Content-Type={request.content_type}, Files={list(request.files.keys())}, Content-Length={request.content_length}")
        # Accept multipart file upload or a JSON file_path
        if 'file' in request.files:
            f = request.files['file']
            filename = f.filename or 'upload.bin'
            tmp_path = f"/tmp/cybershield_upload_{int(time.time()*1000)}_{filename}"
            f.save(tmp_path)
            threat_level, indicators = engine.file_scanner.scan_file(tmp_path)
            # run YARA matches if available
            yara_matches = []
            try:
                if getattr(engine, 'yara_rules', None):
                    for comp in engine.yara_rules:
                        try:
                            m = comp.match(filepath=tmp_path)
                            for mm in m:
                                # mm may be a yara Match object or dict
                                try:
                                    yara_matches.append(mm.rule)
                                except Exception:
                                    try:
                                        yara_matches.append(str(mm))
                                    except Exception:
                                        pass
                        except Exception:
                            pass
            except Exception:
                yara_matches = []
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        else:
            # use silent to avoid 415 errors when Content-Type isn't JSON
            data = request.get_json(silent=True) or {}
            file_path = data.get('file_path', '')
            if not file_path:
                return jsonify({'error': 'file_path or file upload required'}), 400
            threat_level, indicators = engine.file_scanner.scan_file(file_path)

        # Determine status with YARA info
        try:
            ym = yara_matches if 'yara_matches' in locals() else []
        except Exception:
            ym = []

        status = threat_level.value
        if ym:
            # heuristics: if rule name contains ransomware or ransom -> malicious
            if any('ransom' in r.lower() for r in ym):
                status = 'Malicious'
            else:
                status = 'Suspicious'

        # store detection in engine threats if significant
        if ym or (threat_level.value != 'SAFE'):
            try:
                details = {'yara_matches': ym, 'indicators': indicators}
                t = Threat(
                    id=_hashlib.md5((str(time.time()) + (filename if 'filename' in locals() else '')).encode()).hexdigest()[:8],
                    type='SUSPICIOUS_FILE' if ym else 'SUSPICIOUS_FILE',
                    severity=status.upper(),
                    name=(filename if 'filename' in locals() else (file_path if 'file_path' in locals() else 'upload')),
                    description=f"YARA matches: {', '.join(ym)}" if ym else f"Indicators: {', '.join(indicators)}",
                    timestamp=datetime.now().isoformat(),
                    details={'path': (file_path if 'file_path' in locals() else ''), **details}
                )
                engine.all_threats.append(t)
            except Exception:
                pass

        return jsonify({
            'threat_level': threat_level.value,
            'status': status,
            'indicators': indicators,
            'yara_matches': ym,
            'is_safe': status == 'Clean' or status == 'SAFE',
        }), 200
    
    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/log-analysis', methods=['GET'])
def get_log_analysis():
    """Get user-friendly analysis of network logs"""
    try:
        connections = engine.network_monitor.get_active_connections()
        suspicious = [c for c in connections if c.is_suspicious]
        
        # Convert technical logs to user-friendly descriptions
        analysis = []
        
        for conn in suspicious[-10:]:  # Last 10 suspicious
            if conn.remote_ip and conn.remote_ip != '127.0.0.1':
                description = f"Your system connected to {conn.remote_ip}:{conn.remote_port} via {conn.process_name}. "
                
                if conn.threat_indicator:
                    description += f"Alert: {conn.threat_indicator}. "
                
                if conn.remote_port in [22, 3389]:
                    description += "This remote access port (SSH/RDP) is being used. If you didn't authorize this, it may be suspicious."
                elif conn.remote_port in [53, 80, 443]:
                    description += "This is a normal service port, likely safe."
                elif conn.remote_port > 50000:
                    description += "This is a high-numbered port, potentially used for tunneling or backdoors."
                else:
                    description += "Research this port to determine if it's legitimate."
                
                analysis.append({
                    'connection': f"{conn.remote_ip}:{conn.remote_port}",
                    'process': conn.process_name,
                    'threat_level': 'WARNING' if conn.threat_indicator else 'SUSPICIOUS',
                    'explanation': description,
                })
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'analysis_count': len(analysis),
            'analysis': analysis,
        }), 200
    
    except Exception as e:
        logger.error(f"Error analyzing logs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    """Comprehensive dashboard data (all real-time info in one call)"""
    try:
        metrics = engine.system_monitor.get_system_metrics()
        connections = engine.network_monitor.get_active_connections()
        threats = list(engine.all_threats)[-20:]
        
        suspicious_conns = [c for c in connections if c.is_suspicious]
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'system': {
                'cpu_percent': metrics.cpu_percent,
                'memory_percent': metrics.memory_percent,
                'memory_mb': metrics.memory_mb,
                'disk_percent': metrics.disk_percent,
                'health_percent': metrics.system_health_percent,
                'status': metrics.status,
                'process_count': metrics.process_count,
            },
            'security': {
                'threats_total': len(engine.all_threats),
                'threats_recent': len(threats),
                'suspicious_connections': len(suspicious_conns),
                'status': metrics.status,
            },
            'threats': [t.to_dict() for t in threats],
            'connections': [
                {
                    'remote_ip': c.remote_ip,
                    'remote_port': c.remote_port,
                    'process': c.process_name,
                    'is_suspicious': c.is_suspicious,
                }
                for c in suspicious_conns[:20]
            ],
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting dashboard: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'running', 'timestamp': datetime.now().isoformat()}), 200


@app.route('/api/stream', methods=['GET'])
def stream_events():
    """Server-Sent Events stream of dashboard snapshots (simple implementation)."""
    def event_stream():
        while True:
            try:
                data = engine.run_threat_detection()
                yield f"data: {json.dumps(data)}\n\n"
                time.sleep(2)
            except GeneratorExit:
                break
            except Exception as e:
                logger.error(f"Stream error: {e}")
                time.sleep(2)

    return Response(event_stream(), mimetype='text/event-stream')


if __name__ == '__main__':
    logger.info("Starting CYBERSHIELD PRO API Server...")
    logger.info("API running on http://localhost:5000")
    logger.info("Endpoints:")
    logger.info("  GET  /api/status")
    logger.info("  GET  /api/metrics")
    logger.info("  GET  /api/threats")
    logger.info("  GET  /api/network")
    logger.info("  POST /api/scan-url")
    logger.info("  POST /api/scan-file")
    logger.info("  GET  /api/log-analysis")
    logger.info("  GET  /api/dashboard")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
