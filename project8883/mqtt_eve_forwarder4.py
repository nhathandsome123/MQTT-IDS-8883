#!/usr/bin/env python3
import json
import time
import os
import re  # For clean_payload_for_json
from datetime import datetime, timedelta
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# --- Configuration ---
EVE_DIR = os.getenv("EVE_DIR", "/var/log/suricata")
INFLUX_URL = os.getenv("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iot-admin-token-123")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iot-org")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "iot-data") # Dùng tên bucket từ docker-compose

# Cache: (src_ip, src_port) -> (client_id, last_seen)
client_map = {}
CACHE_TTL = 86400  # 24 hours

PAYLOAD_LIMIT = int(os.getenv("PAYLOAD_LIMIT", "1024")) # Lấy từ env

# Danh sách các trường mong muốn (đã đầy đủ)
MQTT_FIELDS_TOP = [
    "dup", "message_id", "password", "protocol_string", "protocol_version",
    "qos", "retain", "return_code", "session_present", "topic", "username"
]
MQTT_FIELDS_JSON = ["topics", "qos_granted", "reason_codes"]
MQTT_FIELDS_FLAGS = ["clean_session", "password", "username", "will", "will_retain"]


def get_latest_eve_file(directory):
    """Tìm file eve.json mới nhất (không nén) trong thư mục."""
    files = [f for f in os.listdir(directory) if f.startswith("eve.json") and not f.endswith(".gz")]
    if not files:
        return None
    files.sort(key=lambda x: os.path.getmtime(os.path.join(directory, x)), reverse=True)
    return os.path.join(directory, files[0])


def tail_f(directory):
    """Theo dõi file eve.json, xử lý việc file xoay vòng (log rotation)."""
    current_file = get_latest_eve_file(directory)
    if not current_file:
        print(f"No eve.json found in {directory}, retrying...")
        while not current_file:
            time.sleep(5)
            current_file = get_latest_eve_file(directory)
    print(f"Tailing: {current_file}")

    while True:
        with open(current_file, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    new_file = get_latest_eve_file(directory)
                    if new_file and new_file != current_file:
                        print(f"File rotated -> {new_file}")
                        current_file = new_file
                        break
                    time.sleep(0.1)
                    continue
                yield line


def cleanup_client_map():
    """Xóa các client_id cũ khỏi cache."""
    now = datetime.utcnow()
    expired = [k for k, (_, t) in client_map.items() if (now - t).total_seconds() > CACHE_TTL]
    for k in expired:
        del client_map[k]
    if expired:
        print(f"[CLEANUP] Removed {len(expired)} expired clients")


def clean_payload_for_json(payload_str):
    """Làm sạch payload cơ bản."""
    payload_str = re.sub(r'"[^"]*\s*\*\s*\d+"', '"REPEATED_DATA"', payload_str)
    return payload_str


# <<< ĐÃ XÓA HÀM process_http_event >>>


def process_mqtt_event(event, write_api):
    """Xử lý tất cả sự kiện MQTT và Flow (đã vá)."""
    timestamp = event.get("timestamp")
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    src_port = event.get("src_port")
    dest_port = event.get("dest_port")

    if not src_ip:
        return

    client_id = "unknown"

    # Lấy client_id từ cache
    key = (src_ip, src_port)
    if key in client_map:
        client_id, last_seen = client_map[key]
        client_map[key] = (client_id, datetime.utcnow())

    # 1. XỬ LÝ FLOW EVENT (cho Rule 2)
    if event.get("app_proto") == "mqtt" and event.get("event_type") == "flow":
        flow = event.get("flow", {})
        bytes_toserver = flow.get("bytes_toserver", 0)
        pkts_toserver = flow.get("pkts_toserver", 0)
        state = flow.get("state", "unknown")

        mqtt_type = "publish_flow" if bytes_toserver > 200 else "flow"

        point = (
            Point("mqtt_event")
            .tag("mqtt_type", mqtt_type)
            .tag("src_ip", src_ip)
            .tag("src_port", str(src_port) if src_port else "")
            .tag("dest_ip", dest_ip or "")
            .tag("dest_port", str(dest_port) if dest_port else "")
            .tag("client_id", client_id) # Dùng client_id từ cache
            .field("bytes_toserver", bytes_toserver)
            .field("pkts_toserver", pkts_toserver)
            .field("state", state)
            .field("topic", "unknown_flow_topic") # Đảm bảo field 'topic' tồn tại
            .field("payload_raw", f"Flow data: {bytes_toserver} bytes")
            .time(timestamp, WritePrecision.NS)
        )
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        print(
            f"[WRITE FLOW] {mqtt_type} | {src_ip}:{src_port or '?'} | client_id: {client_id} | bytes: {bytes_toserver}")
        return

    # 2. XỬ LÝ SỰ KIỆN APP-LAYER (connect, publish, subscribe, connack, v.v.)
    mqtt_data = event.get("mqtt", {})
    if not mqtt_data:
        return

    mqtt_type = list(mqtt_data.keys())[0]  # vd: 'connect', 'publish', 'subscribe', 'connack'
    mqtt_value = mqtt_data[mqtt_type]  # data bên trong

    # Cập nhật client_id từ CONNECT
    if mqtt_type == "connect" and "client_id" in mqtt_value:
        client_id = mqtt_value["client_id"]
        key = (src_ip, src_port)
        client_map[key] = (client_id, datetime.utcnow())


    # 3. XỬ LÝ ĐẶC BIỆT CHO 'SUBSCRIBE' (cho Rule 5, 6)
    if mqtt_type == "subscribe" and "topics" in mqtt_value:
        all_topics = mqtt_value.get("topics", [])
        msg_id = mqtt_value.get("message_id")
        
        print(f"[WRITE SUB] {mqtt_type} | {src_ip}:{src_port or '?'} | client_id: {client_id} | {len(all_topics)} topics")

        for sub_topic in all_topics:
            topic_name = sub_topic.get("topic")
            topic_qos = sub_topic.get("qos")
            
            if not topic_name:
                continue

            point = (
                Point("mqtt_event")
                .tag("mqtt_type", mqtt_type)
                .tag("src_ip", src_ip)
                .tag("src_port", str(src_port) if src_port else "")
                .tag("dest_ip", dest_ip or "")
                .tag("dest_port", str(dest_port) if dest_port else "")
                .tag("client_id", client_id)
                .time(timestamp, WritePrecision.NS)
            )

            # Ghi CÁC TRƯỜNG GIỐNG NHƯ PUBLISH
            point = point.field("topic", topic_name) # Đây là trường quan trọng
            if topic_qos is not None:
                point = point.field("qos", topic_qos)
            if msg_id is not None:
                point = point.field("message_id", msg_id)
            
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        
        return # Đã xử lý xong 'subscribe', thoát

    # 4. XỬ LÝ CHUNG CHO CÁC GÓI TIN KHÁC (Connect, Publish, Connack, Suback, v.v.)
    
    point = (
        Point("mqtt_event")
        .tag("mqtt_type", mqtt_type)
        .tag("src_ip", src_ip)
        .tag("src_port", str(src_port) if src_port else "")
        .tag("dest_ip", dest_ip or "")
        .tag("dest_port", str(dest_port) if dest_port else "")
        .tag("client_id", client_id)
        .time(timestamp, WritePrecision.NS)
    )

    # 1. Các trường top-level (Gồm: qos, retain, return_code, v.v.)
    for field in MQTT_FIELDS_TOP:
        if field in mqtt_value:
            point = point.field(field, mqtt_value[field])

    # 2. Các trường là JSON/list (Bỏ qua 'topics' vì đã xử lý)
    for field in MQTT_FIELDS_JSON:
        if field == "topics": continue
        if field in mqtt_value:
            point = point.field(field, json.dumps(mqtt_value[field]))

    # 3. Các trường 'flags' (cho 'connect')
    if "flags" in mqtt_value and isinstance(mqtt_value["flags"], dict):
        flags = mqtt_value["flags"]
        for flag in MQTT_FIELDS_FLAGS:
            if flag in flags:
                point = point.field(f"flags_{flag}", flags[flag])

    # 4. Trường client_id (cho Rule 8)
    if "client_id" in mqtt_value:
        point = point.field("client_identifier", mqtt_value["client_id"])

    # 5. Xử lý payload (cho 'publish' - Rule 3)
    if mqtt_type == "publish":
        payload = mqtt_value.get("payload") or mqtt_value.get("payload_printable", "")
        if payload:
            cleaned = clean_payload_for_json(str(payload))
            point = point.field("payload_raw", cleaned[:PAYLOAD_LIMIT])

            # Thử flatten payload nếu là JSON
            try:
                payload_data = json.loads(cleaned)
                if isinstance(payload_data, dict):
                    def flatten_payload(d, parent_key='payload', sep='_'):
                        items = []
                        for k, v in d.items():
                            new_key = f"{parent_key}{sep}{k}" if parent_key else k
                            if isinstance(v, dict):
                                items.extend(flatten_payload(v, new_key, sep=sep).items())
                            else:
                                items.append((new_key, str(v)))
                        return dict(items)

                    payload_flattened = flatten_payload(payload_data)
                    for pkey, pvalue in payload_flattened.items():
                        point = point.field(pkey, pvalue)
                else:
                    point = point.field("payload_value", str(payload_data))
            except json.JSONDecodeError:
                pass  # Đã ghi payload_raw

    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
    print(f"[WRITE] {mqtt_type} | {src_ip}:{src_port or '?'} | client_id: {client_id}")

    if len(client_map) % 100 == 0:
        cleanup_client_map()


def main():
    print("MQTT EVE Forwarder (MQTT ONLY) Starting...")
    
    # Thử kết nối tới InfluxDB trước khi bắt đầu
    while True:
        try:
            client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG, timeout=10000)
            health = client.health()
            if health.status == "pass":
                print(f"[INFO] InfluxDB health: {health.status}")
                break
            else:
                print(f"[WARN] InfluxDB health: {health.status}. Retrying...")
        except Exception as e:
            print(f"[ERROR] Cannot connect to InfluxDB ({INFLUX_URL}). Retrying... Error: {e}")
        time.sleep(10)
        
    write_api = client.write_api(write_options=SYNCHRONOUS)

    for line in tail_f(EVE_DIR):
        try:
            event = json.loads(line)
            event_type = event.get("event_type")
            app_proto = event.get("app_proto")

            # <<< ĐÃ THAY ĐỔI >>>
            # Chỉ xử lý sự kiện MQTT
            if event_type == "mqtt" or (app_proto == "mqtt" and event_type == "flow"):
                process_mqtt_event(event, write_api)
            
            # (Các sự kiện khác như 'http', 'alert', 'dns' sẽ bị bỏ qua)

        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[ERROR] Lỗi xử lý dòng: {e} | Dòng: {line[:200]}...")


if __name__ == "__main__":
    main()