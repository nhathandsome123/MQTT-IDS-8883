#!/usr/bin/env python3
import json
import time
import os
import re
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# --- Configuration ---
EVE_DIR = os.getenv("EVE_DIR", "/var/log/suricata")
INFLUX_URL = os.getenv("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iot-admin-token-123")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iot-org")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "iot-data")

# Cache: flow_id -> client_id
client_map = {} 
PAYLOAD_LIMIT = int(os.getenv("PAYLOAD_LIMIT", "1024"))

# Danh sách các trường mong muốn
MQTT_FIELDS_TOP = [
    "dup", "message_id", "password", "protocol_string", "protocol_version",
    "qos", "retain", "return_code", "session_present", "topic", "username"
]
MQTT_FIELDS_JSON = ["topics", "qos_granted", "reason_codes"]
MQTT_FIELDS_FLAGS = ["clean_session", "password", "retain", "will", "will_qos", "will_retain"]

def get_latest_eve_file(directory):
    """Tìm file eve.json mới nhất trong thư mục."""
    try:
        files = [f for f in os.listdir(directory) if f.startswith("eve") and f.endswith(".json")]
        if not files:
            print(f"[ERROR] Không tìm thấy file eve.json nào trong {directory}")
            return None
        files.sort(key=lambda x: os.path.getmtime(os.path.join(directory, x)), reverse=True)
        return os.path.join(directory, files[0])
    except FileNotFoundError:
        print(f"[ERROR] Thư mục không tồn tại: {directory}")
        return None
    except Exception as e:
        print(f"[ERROR] Lỗi khi tìm file EVE: {e}")
        return None

def tail_f(directory):
    """Theo dõi file EVE mới nhất."""
    current_file_path = None
    file = None
    
    while True:
        latest_file_path = get_latest_eve_file(directory)
        
        if not latest_file_path:
            print(f"[WARN] Đang chờ file EVE xuất hiện trong {directory}...")
            time.sleep(10)
            continue
            
        if latest_file_path != current_file_path:
            if file:
                file.close()
            try:
                file = open(latest_file_path, "r")
                current_file_path = latest_file_path
                print(f"[INFO] Đang theo dõi file: {current_file_path}")
                file.seek(0, 2) 
            except Exception as e:
                print(f"[ERROR] Không thể mở file {latest_file_path}: {e}")
                file = None
                current_file_path = None
                time.sleep(10)
                continue

        line = file.readline()
        if not line:
            # Xử lý logrotate
            try:
                if os.stat(current_file_path).st_size == 0:
                    print("[INFO] File EVE bị truncate. Mở lại...")
                    file.close()
                    file = open(current_file_path, "r")
            except FileNotFoundError:
                print("[INFO] File EVE bị di chuyển. Tìm file mới...")
                file = None
            except Exception as e:
                print(f"[ERROR] Lỗi khi kiểm tra file: {e}")
            
            time.sleep(0.1)
            continue
        
        yield line


def clean_payload_for_json(payload_str):
    """Loại bỏ các ký tự không hợp lệ (control chars) khỏi payload."""
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", payload_str)


def process_mqtt_event(event, write_api):
    """Xử lý tất cả sự kiện MQTT và Flow (đã sửa lỗi gộp trường)."""
    timestamp = event.get("timestamp")
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    src_port = event.get("src_port")
    dest_port = event.get("dest_port")
    
    flow_id = event.get("flow_id")
    if not flow_id:
        return

    # Lấy client_id từ cache nếu có
    client_id = client_map.get(flow_id, "unknown")

    # 1. XỬ LÝ FLOW EVENT
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
            .tag("client_id", client_id) 
            .field("bytes_toserver", bytes_toserver)
            .field("pkts_toserver", pkts_toserver)
            .field("state", state)
            .field("topic", "unknown_flow_topic")
            .field("payload_raw", f"Flow data: {bytes_toserver} bytes")
            .time(timestamp, WritePrecision.NS)
        )
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        
        if state == "closed":
            if flow_id in client_map:
                del client_map[flow_id]
            
        print(
            f"[WRITE FLOW] {mqtt_type} | {src_ip}:{src_port or '?'} | client_id: {client_id} | bytes: {bytes_toserver}")
        return

    # 2. XỬ LÝ SỰ KIỆN APP-LAYER
    mqtt_data = event.get("mqtt", {})
    if not mqtt_data:
        return

    # <<< THAY ĐỔI: Xác định loại sự kiện chính >>>
    # Log của bạn cho thấy 'connect' và 'connack' đi cùng nhau.
    # Chúng ta sẽ ưu tiên 'connect' làm type chính.
    mqtt_type = "unknown"
    if "connect" in mqtt_data:
        mqtt_type = "connect"
    elif "publish" in mqtt_data:
        mqtt_type = "publish"
    elif "subscribe" in mqtt_data:
        mqtt_type = "subscribe"
    elif mqtt_data:
        mqtt_type = list(mqtt_data.keys())[0] # Fallback

    # 3. XỬ LÝ ĐẶC BIỆT CHO 'SUBSCRIBE'
    if mqtt_type == "subscribe":
        topics = mqtt_data.get("subscribe", {}).get("topics", [])
        for sub_topic in topics:
            if isinstance(sub_topic, dict):
                topic_name = sub_topic.get("topic")
                qos = sub_topic.get("qos", 0)
            else:
                topic_name = str(sub_topic)
                qos = 0
                
            if not topic_name:
                continue

            point = (
                Point("mqtt_event")
                .tag("mqtt_type", "subscribe")
                .tag("src_ip", src_ip)
                .tag("src_port", str(src_port) if src_port else "")
                .tag("dest_ip", dest_ip or "")
                .tag("dest_port", str(dest_port) if dest_port else "")
                .tag("client_id", client_id)
                .field("topic", topic_name)
                .field("qos", qos)
                .field("message_id", mqtt_data.get("subscribe", {}).get("message_id", 0))
                .field("payload_raw", f"Subscribe to: {topic_name}")
                .time(timestamp, WritePrecision.NS)
            )
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
            
        print(f"[WRITE SUB] {mqtt_type} | {src_ip}:{src_port or '?'} | client_id: {client_id} | topics: {len(topics)}")
        return

    # 4. XỬ LÝ CHUNG (CONNECT, PUBLISH,...)
    point = (
        Point("mqtt_event")
        .tag("mqtt_type", mqtt_type)
        .tag("src_ip", src_ip)
        .tag("src_port", str(src_port) if src_port else "")
        .tag("dest_ip", dest_ip or "")
        .tag("dest_port", str(dest_port) if dest_port else "")
        .tag("client_id", client_id) # Sẽ được cập nhật ngay sau đây
        .time(timestamp, WritePrecision.NS)
    )
    
    # <<< THAY ĐỔI LỚN: Gộp tất cả các trường từ các sub-object (connect, connack, v.v.) >>>
    flat_fields = {}
    for key, value_dict in mqtt_data.items():
        if isinstance(value_dict, dict):
            flat_fields.update(value_dict)
    
    # Cập nhật client_id từ dữ liệu đã gộp
    if "client_id" in flat_fields:
        client_id = flat_fields["client_id"]
        point = point.tag("client_id", client_id) # Cập nhật tag
        if mqtt_type == "connect":
            client_map[flow_id] = client_id # Cập nhật cache

    if mqtt_type == "disconnect":
        if flow_id in client_map:
            del client_map[flow_id]
    
    # 1. Các trường top-level (từ tất cả các sub-object đã gộp)
    for field in MQTT_FIELDS_TOP:
        if field in flat_fields:
            # Ghi cả 'username' (từ connect) và 'return_code' (từ connack)
            point = point.field(field, flat_fields[field])

    # 2. Các trường JSON
    for field in MQTT_FIELDS_JSON:
        if field in flat_fields:
            try:
                json_str = json.dumps(flat_fields[field])
                point = point.field(field, json_str)
            except TypeError:
                point = point.field(field, str(flat_fields[field]))

    # 3. Các trường 'flags'
    flags_dict = flat_fields.get("flags") 
    if isinstance(flags_dict, dict):
         for flag in MQTT_FIELDS_FLAGS:
            if flag in flags_dict:
                point = point.field(f"flag_{flag}", flags_dict[flag])

    # 4. Ghi lại client_id
    if "client_id" in flat_fields:
        point = point.field("client_identifier", flat_fields["client_id"])
    
    # 5. Xử lý payload (chỉ cho 'publish')
    payload_raw = "N/A"
    if mqtt_type == "publish":
        payload_str = flat_fields.get("payload", "")
        payload_len = len(payload_str)
        point = point.field("payload_len", payload_len)

        if payload_len > 0:
            try:
                cleaned_payload = clean_payload_for_json(payload_str)
                payload_raw = cleaned_payload[:PAYLOAD_LIMIT]
                point = point.field("payload_raw", payload_raw)
                try:
                    payload_json = json.loads(cleaned_payload)
                    if isinstance(payload_json, dict):
                        for k, v in payload_json.items():
                            if isinstance(v, (str, int, float, bool)):
                                point = point.field(f"p_{k}", v)
                except json.JSONDecodeError:
                    pass
            except Exception:
                pass
    
    if "payload_raw" not in point._fields:
         point = point.field("payload_raw", payload_raw)

    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
    print(f"[WRITE] {mqtt_type} | {src_ip}:{src_port or '?'} | client_id: {client_id} | RC: {flat_fields.get('return_code', 'N/A')}")


def main():
    print("MQTT EVE Forwarder (ĐÃ SỬA LỖI GỘP FIELD) Starting...")
    
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

            if event_type == "mqtt" or (app_proto == "mqtt" and event_type == "flow"):
                process_mqtt_event(event, write_api)

        except json.JSONDecodeError:
            print(f"[WARN] Bỏ qua dòng JSON không hợp lệ: {line[:100]}...")
        except Exception as e:
            print(f"[ERROR] Lỗi xử lý sự kiện: {e} | DATA: {line[:200]}...")

if __name__ == "__main__":
    main()