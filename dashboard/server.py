"""
Sentinela - Web Server
Serves the dashboard and exposes API endpoints for AI analysis.
Run with: python dashboard/server.py
Then open: http://localhost:8080
"""

import os
import sys
import json
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS

# Add parent dir to path so we can import analyst module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyst.analyze import (
    generate_shift_summary,
    generate_threat_narratives,
    investigate_ip,
    generate_config_suggestions,
)
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='.')
CORS(app)

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route('/')
def index():
    return send_from_directory(DASHBOARD_DIR, 'index.html')


@app.route('/api/analyze')
def analyze():
    analysis_type = request.args.get('type', '')
    lookback = int(request.args.get('minutes', 120))

    try:
        if analysis_type == 'summary':
            result = generate_shift_summary(minutes=lookback)
        elif analysis_type == 'threats':
            result = generate_threat_narratives(minutes=lookback)
        elif analysis_type == 'config':
            result = generate_config_suggestions(minutes=lookback)
        elif analysis_type == 'ip':
            ip = request.args.get('ip', '').strip()
            if not ip:
                return jsonify({'error': 'IP address is required'}), 400
            result = investigate_ip(ip)
        else:
            return jsonify({'error': f'Unknown analysis type: {analysis_type}'}), 400

        return jsonify({'result': result})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


@app.route('/api/es/dashboard')
def es_dashboard():
    """Proxy dashboard aggregations from Elasticsearch."""
    from elasticsearch import Elasticsearch
    es = Elasticsearch(os.getenv('ES_HOST', 'http://localhost:9200'))
    index = os.getenv('ES_INDEX', 'sentinela-events')
    try:
        result = es.search(index=index, body={
            "query": {"range": {"timestamp": {"gte": "now-24h"}}},
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "by_type":     {"terms": {"field": "source_type", "size": 10}},
                "by_tag":      {"terms": {"field": "tags", "size": 20}},
                "top_ips": {
                    "filter": {"terms": {"severity": ["high", "critical"]}},
                    "aggs": {"ips": {"terms": {"field": "src_ip", "size": 8}}}
                },
                "recent_bad": {
                    "filter": {"terms": {"severity": ["high", "critical", "medium"]}},
                    "aggs": {
                        "hits": {
                            "top_hits": {
                                "sort": [{"timestamp": {"order": "desc"}}],
                                "size": 15
                            }
                        }
                    }
                }
            },
            "size": 0
        })
        return jsonify(result.body)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/es/events')
def es_events():
    """Proxy event search from Elasticsearch."""
    from elasticsearch import Elasticsearch
    es = Elasticsearch(os.getenv('ES_HOST', 'http://localhost:9200'))
    index = os.getenv('ES_INDEX', 'sentinela-events')

    severity = request.args.get('severity', '')
    source_type = request.args.get('type', '')

    must = [{"range": {"timestamp": {"gte": "now-24h"}}}]
    if severity:
        must.append({"term": {"severity": severity}})
    if source_type:
        must.append({"term": {"source_type": source_type}})

    try:
        result = es.search(index=index, body={
            "query": {"bool": {"must": must}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 100
        })
        return jsonify(result.body)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    print(f"\n  Sentinela dashboard running at http://localhost:{port}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host='0.0.0.0', port=port, debug=False)