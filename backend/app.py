from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import joblib
import numpy as np
import pandas as pd
import logging
import traceback
from datetime import datetime

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

# Загрузка моделей
try:
    model = joblib.load('model/model.pkl')
    scaler = joblib.load('model/scaler.pkl')
    encoders = joblib.load('model/encoders.pkl')
    features_order = joblib.load('model/features.pkl')
    if isinstance(features_order, pd.DataFrame):
        features_order = features_order.columns.tolist()
    elif isinstance(features_order, dict):
        features_order = list(features_order.keys())
    logging.info(f"Порядок признаков: {features_order}")
except Exception as e:
    logging.critical(f"Ошибка загрузки моделей: {e}")
    raise

DEFAULT_VALUES = {
    'ct_srv_src': 0, 'ct_state_ttl': 0, 'dttl': 64,
    'sload': 0, 'dload': 0, 'swin': 64240, 'dwin': 64240
}
PROTOCOL_MAP = {6: 'tcp', 17: 'udp', 1: 'icmp', 2: 'igmp', 58: 'ipv6-icmp'}
STATE_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}

def get_anomaly_type(pkt):
    """Определение типа аномалии через эвристику."""
    try:
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            if syn and not ack:
                return 'SYN Flood'
            if len(pkt) > 1500:
                return 'Oversized Packet'
        if pkt.haslayer(UDP) and len(pkt) > 1500:
            return 'Oversized Packet'
        if pkt.haslayer(ICMP):
            return 'ICMP Anomaly'
        return ''
    except:
        return ''

def get_protocol_service(pkt):
    """Определение сервиса по порту."""
    try:
        if pkt.haslayer(TCP):
            s, d = pkt[TCP].sport, pkt[TCP].dport
            if 80 in (s, d): return 'http'
            if 443 in (s, d): return 'https'
            if 22 in (s, d): return 'ssh'
            return 'tcp'
        if pkt.haslayer(UDP):
            s, d = pkt[UDP].sport, pkt[UDP].dport
            if 53 in (s, d): return 'dns'
            if 67 in (s, d) or 68 in (s, d): return 'dhcp'
            return 'udp'
        if pkt.haslayer(ICMP):
            return 'icmp'
        return 'other'
    except:
        return 'other'


def get_connection_state ( pkt ) :
    """Определение состояния соединения по TCP-флагам."""
    try :
        if not pkt.haslayer ( TCP ) :
            return 'EST'

        flags = str ( pkt [ TCP ].flags )
        state_parts = [ ]

        for f in flags :
            if f in STATE_FLAGS :
                state_parts.append ( STATE_FLAGS [ f ] )

        return '-'.join ( state_parts ) if state_parts else 'EST'
    except Exception as e :
        logging.warning ( f"Ошибка определения состояния: {e}" )
        return 'EST'

def prepare_features(pkt):
    """Подготовка признаков для ML-модели."""
    try:
        if not pkt.haslayer(IP):
            return None, None, None
        ip = pkt[IP]
        proto = PROTOCOL_MAP.get(ip.proto, 'other')
        service = get_protocol_service(pkt)
        state = get_connection_state(pkt)

        raw = {
            'dur': 0.0, 'proto': proto, 'service': service, 'state': state,
            'sbytes': len(pkt), 'dbytes': 0, 'sttl': ip.ttl,
            **DEFAULT_VALUES
        }
        for col in ('proto', 'service', 'state'):
            if col in encoders:
                try:
                    df_enc = pd.DataFrame([[str(raw[col])]], columns=[col])
                    raw[col] = float(encoders[col].transform(df_enc)[0][0])
                except:
                    raw[col] = -1.0
        vec = [float(raw.get(c, -1.0)) for c in features_order]
        return pd.DataFrame([vec], columns=features_order), proto, service
    except Exception as e:
        logging.error(f"prepare_features: {e}")
        traceback.print_exc()
        return None, None, None

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify(error="Файл не загружен"), 400
        f = request.files['file']
        if not f.filename.lower().endswith(('.pcap', '.pcapng')):
            return jsonify(error="Неподдерживаемый формат"), 400

        packets = rdpcap(f)
        results = []
        for pkt in packets[:10000]:
            try:
                if not pkt.haslayer(IP):
                    continue
                ip = pkt[IP]

                # Эвристика аномалий
                anomaly_heur = get_anomaly_type(pkt)
                if anomaly_heur:
                    proto = PROTOCOL_MAP.get(ip.proto, 'other')
                    svc = get_protocol_service(pkt)
                    display_proto = svc if svc != 'other' else proto
                    results.append({
                        'timestamp': datetime.fromtimestamp(float(pkt.time)).isoformat(),
                        'src_ip': ip.src, 'dst_ip': ip.dst,
                        'protocol': display_proto,
                        'prediction': 'Anomaly',
                        'confidence': 1.0,
                        'anomaly_details': anomaly_heur,  # Ключевое изменение!
                        'details': {'bytes': len(pkt), 'ttl': ip.ttl}
                    })
                    continue

                # ML-модель
                features_df, proto, service = prepare_features(pkt)
                if features_df is None:
                    continue
                Xs = scaler.transform(features_df)
                cat = model.predict(Xs)[0]
                proba = model.predict_proba(Xs)[0] if hasattr(model, 'predict_proba') else None

                status = 'Normal' if str(cat).lower() == 'normal' else 'Anomaly'
                confidence = proba[list(model.classes_).index(cat)] if proba is not None else 1.0
                display_proto = service if service != 'other' else proto

                results.append({
                    'timestamp': datetime.fromtimestamp(float(pkt.time)).isoformat(),
                    'src_ip': ip.src, 'dst_ip': ip.dst,
                    'protocol': display_proto,
                    'prediction': status,
                    'confidence': round(float(confidence), 2),
                    'anomaly_details': '' if status == 'Normal' else str(cat),  # Ключевое изменение!
                    'details': {'bytes': len(pkt), 'ttl': ip.ttl}
                })

            except Exception as e:
                logging.error(f"Ошибка обработки пакета: {e}")
                traceback.print_exc()

        return jsonify(results)

    except Exception as e:
        logging.error(traceback.format_exc())
        return jsonify(error="Внутренняя ошибка"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)