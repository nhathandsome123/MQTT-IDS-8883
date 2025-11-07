#!/usr/bin/env python3
import time
import re
import pandas as pd
import ipaddress
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import yagmail
import os
import warnings
import json

# --- Ignore warnings ---
warnings.filterwarnings("ignore", message=".*arrow.*", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*DeprecationWarning:.*pandas.*", category=DeprecationWarning)

# --- Configuration (env override) ---
INFLUX_URL = os.getenv("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iot-admin-token-123")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iot-org")
SRC_BUCKET = os.getenv("SRC_BUCKET", "iot-data")
ALERT_BUCKET = os.getenv("ALERT_BUCKET", "iot-data") 

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO", "").split(",")

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "300"))
PAYLOAD_LIMIT = int(os.getenv("PAYLOAD_LIMIT", "1024"))
RETAIN_QOS_LIMIT = int(os.getenv("RETAIN_QOS_LIMIT", "5"))
RECONNECT_LIMIT = int(os.getenv("RECONNECT_LIMIT", "10"))
PUBLISH_FLOOD_LIMIT = int(os.getenv("PUBLISH_FLOOD_LIMIT", "100"))

# --- *** THAY ĐỔI THEO YÊU CẦU *** ---
ENUM_LIMIT = int(os.getenv("ENUM_LIMIT", "10")) # Giảm từ 20 xuống 10
BRUTE_FORCE_LIMIT = int(os.getenv("BRUTE_FORCE_LIMIT", "5")) # Thêm mới, ngưỡng 5
# --- *** KẾT THÚC THAY ĐỔI *** ---

ALERT_COOLDOWN = int(os.getenv("ALERT_COOLDOWN", "3600")) # 1 giờ

# --- Cấu hình Rule ---
ALLOWED_TOPICS_REGEX = [
    r"^/devices/+/events$",
    r"^/devices/+/config$",
    r"^/admin/status$",
    r"^factory/production/.*",
    r"^factory/office/.*",
    r"^factory/energy/.*",
    r"^factory/security/.*",
    r"^factory/storage/.*",
]
SUSPICIOUS_CLIENT_ID_PREFIXES = [
    "mqtt-explorer", "mqtt-spy", "mosquitto_sub", "mosquitto_pub", "MQTTBox"
]
SUSPICIOUS_PAYLOAD_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
    "../", "%2F", "%5C", "passwd", "shadow", "credentials"
]

# --- CẤU HÌNH WHITELIST ---
WHITELISTED_CLIENT_PREFIXES = [
    "giamdoc_gay", "truongphong_security", "truongphong_office", "truongphong_production",
    "sensor_", "meter_", "printer_", "pc_", "plc_", "robot_", "cam_", "access_", "forklift_",  
]

# --- Global state ---
yag = None
if EMAIL_USER and EMAIL_PASS and EMAIL_TO:
    try:
        yag = yagmail.SMTP(EMAIL_USER, EMAIL_PASS)
        print("[INFO] Email client initialized.")
    except Exception as e:
        print(f"[WARN] Could not initialize email client: {e}")

# (rule_name, key) -> timestamp
alert_cooldown_cache = {}

def should_alert(key):
    """Check if an alert for this key is in cooldown."""
    now = time.time()
    if key in alert_cooldown_cache:
        last_alerted = alert_cooldown_cache[key]
        if (now - last_alerted) < ALERT_COOLDOWN:
            print(f"[COOLDOWN] Skipping alert for {key}")
            return False
    alert_cooldown_cache[key] = now
    return True

def send_email(subject, body):
    if yag and EMAIL_TO:
        print(f"[ALERT] Sending email: {subject}")
        try:
            yag.send(to=EMAIL_TO, subject=subject, contents=body)
        except Exception as e:
            print(f"[ERROR] Failed to send email: {e}")
    else:
        print("[ALERT] Email client not configured, skipping send.")

def write_alert(write_api, rule_name, src_ip, client_id, message):
    """Write an alert to the InfluxDB alert bucket."""
    point = Point("mqtt_alert") \
        .tag("rule", rule_name) \
        .tag("src_ip", str(src_ip)) \
        .tag("client_id", str(client_id)) \
        .field("message", str(message)) \
        .time(datetime.utcnow(), WritePrecision.NS)
    
    write_api.write(bucket=ALERT_BUCKET, org=INFLUX_ORG, record=point)
    print(f"[ALERT] Rule: {rule_name} | Client: {client_id} | IP: {src_ip} | Msg: {message}")


# --- Rule Functions ---

def detect_duplicate_client_id(df, write_api):
    """
    Detects duplicate client_id usage by checking for the same client_id 
    used from MORE THAN ONE UNIQUE SOURCE PORT. This is resilient to 
    Load Balancer/Proxy IPs (fixed src_ip).
    """
    connect_df = df[df["mqtt_type"] == "connect"].copy()
    if connect_df.empty:
        return
        
    # LOGIC MỚI: Nhóm theo client_id và đếm số lượng src_port duy nhất
    # src_port khác nhau => kết nối vật lý khác nhau
    client_ports = connect_df.groupby("client_id")["src_port"].nunique()
    duplicates = client_ports[client_ports > 1] # Nếu có nhiều hơn 1 cổng nguồn sử dụng cùng 1 client_id
    
    for client_id, port_count in duplicates.items():
        if not client_id or client_id == "unknown":
            continue
        
        # Lấy một IP bất kỳ (sẽ là IP của Proxy) để ghi log
        # Đảm bảo cột src_ip có dữ liệu trước khi truy cập
        src_ip = connect_df[connect_df["client_id"] == client_id]["src_ip"].iloc[0] if "src_ip" in connect_df.columns else "unknown"
        
        key = ("duplicate_client_id", client_id)
        if should_alert(key):
            msg = f"Duplicate client_id: '{client_id}' seen using {port_count} different source ports from IP {src_ip} (Proxy)"
            write_alert(write_api, "duplicate_client_id", src_ip, client_id, msg)
            send_email("MQTT Security Alert: Duplicate Client ID", msg)

def detect_reconnect_storm(df, write_api):
    # Detect reconnect storm (rapid connect/disconnect)
    connect_events = df[df["mqtt_type"].isin(["connect", "disconnect"])]
    if connect_events.empty:
        return

    # SỬA: Nhóm theo client_id 
    storm_counts = connect_events.groupby("client_id").size().reset_index(name="count")
    for _, row in storm_counts.iterrows():
        if row["count"] > RECONNECT_LIMIT and row["client_id"] != "unknown":
            
            key = ("reconnect_storm", row["client_id"]) 
            if should_alert(key):
                src_ip = df[df["client_id"] == row["client_id"]]["src_ip"].iloc[0] if "src_ip" in df.columns else "unknown"
                msg = f"Reconnect storm: {row['count']} connect/disconnect events from client '{row['client_id']}' ({src_ip})"
                
                write_alert(write_api, "reconnect_storm", src_ip, row["client_id"], msg)
                send_email("MQTT Security Alert: Reconnect Storm", msg)

def detect_wildcard_abuse(df, write_api):
    # Detect wildcard abuse in subscribe topics
    subscribe_df = df[df["mqtt_type"] == "subscribe"].copy()
    if subscribe_df.empty:
        return

    if "topics" in subscribe_df.columns:
        
        # --- SỬA LỖI LOGIC GIẢI MÃ JSON (Tương tự Topic Enumeration) ---
        sub_df = subscribe_df.dropna(subset=["topics"])[["client_id", "src_ip", "topics"]].copy()
        if sub_df.empty:
            return

        def parse_json_topics(json_string):
            try:
                topics = json.loads(json_string)
                if isinstance(topics, list):
                    return topics
            except Exception:
                pass
            return []

        sub_df["topics_list"] = sub_df["topics"].apply(parse_json_topics)
        exploded_df = sub_df.explode("topics_list")
        
        def get_topic(topic_entry):
            if isinstance(topic_entry, dict):
                return topic_entry.get("topic")
            return str(topic_entry) 

        exploded_df["topic_str"] = exploded_df["topics_list"].apply(get_topic)
        # --- KẾT THÚC SỬA LỖI ---
        
        wildcard_abuse = exploded_df[exploded_df["topic_str"].str.contains(r"#|.*\+.*", na=False)]
        for _, row in wildcard_abuse.iterrows():
            
            # --- *** SỬA LỖI LOGIC *** ---
            # 3 dòng code lỗi (if...continue) đã bị XÓA BỎ khỏi đây.
            # Giờ đây rule sẽ phát hiện '#' và '+'
            
            # Key cooldown là (rule, client_id, topic)
            key = ("wildcard_abuse", row["client_id"], row["topic_str"])
            if should_alert(key):
                src_ip = row.get("src_ip", "unknown")
                msg = f"Wildcard abuse: Client {row['client_id']} ({src_ip}) subscribed to '{row['topic_str']}'"
                write_alert(write_api, "wildcard_abuse", src_ip, row["client_id"], msg)
                send_email("MQTT Security Alert: Wildcard Abuse", msg)

def detect_retain_qos_abuse(df, write_api):
    # Detect high QoS + Retain flag 
    publish_df = df[df["mqtt_type"] == "publish"].copy()
    if publish_df.empty:
        return

    publish_df["qos_num"] = pd.to_numeric(publish_df["qos"], errors="coerce")
    publish_df["retain_bool"] = pd.to_numeric(publish_df["retain"], errors="coerce").fillna(0).astype(bool)

    abuse_df = publish_df[(publish_df["retain_bool"] == True) | (publish_df["qos_num"] > 0)]
    
    # SỬA: Nhóm theo client_id 
    abuse_counts = abuse_df.groupby("client_id").size().reset_index(name="count")
    for _, row in abuse_counts.iterrows():
        if row["count"] > RETAIN_QOS_LIMIT and row["client_id"] != "unknown":
            
            key = ("retain_qos_abuse", row["client_id"])
            if should_alert(key):
                src_ip = df[df["client_id"] == row["client_id"]]["src_ip"].iloc[0] if "src_ip" in df.columns else "unknown"
                msg = f"Retain/QoS abuse: {row['count']} messages with Retain=True and QoS>0 from client '{row['client_id']}' ({src_ip})"
                
                write_alert(write_api, "retain_qos_abuse", src_ip, row["client_id"], msg)
                send_email("MQTT Security Alert: Retain/QoS Abuse", msg)

def detect_payload_anomaly(df, write_api):
    # Detect payload anomalies (large size, suspicious keywords)
    publish_df = df[df["mqtt_type"] == "publish"].dropna(subset=["payload_raw"]).copy()
    if publish_df.empty:
        return

    for _, row in publish_df.iterrows():
        if row["client_id"] == "unknown":
            continue

        payload = str(row["payload_raw"])
        src_ip = row.get("src_ip", "unknown")
        
        # 1. Check size
        if len(payload) > PAYLOAD_LIMIT:
            key = ("payload_large", row["client_id"])
            if should_alert(key):
                msg = f"Large payload: {len(payload)} bytes from {src_ip} ({row['client_id']}) on topic '{row['topic']}'"
                write_alert(write_api, "payload_large", src_ip, row["client_id"], msg)
                send_email("MQTT Security Alert: Large Payload", msg)
        
        # 2. Check keywords
        payload_lower = payload.lower()
        for keyword in SUSPICIOUS_PAYLOAD_KEYWORDS:
            if keyword.lower() in payload_lower:
                key = ("payload_suspicious", row["client_id"], keyword)
                if should_alert(key):
                    msg = f"Suspicious payload: Keyword '{keyword}' found in payload from {src_ip} ({row['client_id']}) on topic '{row['topic']}'"
                    write_alert(write_api, "payload_suspicious", src_ip, row["client_id"], msg)
                    send_email("MQTT Security Alert: Suspicious Payload", msg)
                    break 

def detect_unauthorized_topics(df, write_api):
    # Detect publish/subscribe to unauthorized topics
    if not ALLOWED_TOPICS_REGEX:
        return
        
    allowed_topics_pattern = re.compile("|".join(f"({r})" for r in ALLOWED_TOPICS_REGEX))

    # Xử lý publish (có cột 'topic')
    publish_df = df[df["mqtt_type"] == "publish"].dropna(subset=["topic"]).copy()
    for _, row in publish_df.iterrows():
        if row["client_id"] == "unknown": continue
        topic = row["topic"]
        src_ip = row.get("src_ip", "unknown")
        
        if not allowed_topics_pattern.fullmatch(topic):
            key = ("unauth_topic", row["client_id"], topic)
            if should_alert(key):
                msg = f"Unauthorized publish: Client {row['client_id']} ({src_ip}) published to unauthorized topic '{topic}'"
                write_alert(write_api, "unauth_topic", src_ip, row["client_id"], msg)
                send_email("MQTT Security Alert: Unauthorized Topic", msg)

    # Xử lý subscribe (có cột 'topics' là list/JSON string)
    subscribe_df = df[df["mqtt_type"] == "subscribe"].dropna(subset=["topics"]).copy()
    if "topics" in subscribe_df.columns:
        
        # --- SỬA LỖI LOGIC GIẢI MÃ JSON (Tương tự Topic Enumeration) ---
        sub_df = subscribe_df.dropna(subset=["topics"])[["client_id", "src_ip", "topics"]].copy()
        if sub_df.empty:
            return

        def parse_json_topics(json_string):
            try:
                topics = json.loads(json_string)
                if isinstance(topics, list):
                    return topics
            except Exception:
                pass
            return []

        sub_df["topics_list"] = sub_df["topics"].apply(parse_json_topics)
        exploded_df = sub_df.explode("topics_list")
        
        def get_topic(topic_entry):
            if isinstance(topic_entry, dict): return topic_entry.get("topic")
            return str(topic_entry)
        
        exploded_df["topic_str"] = exploded_df["topics_list"].apply(get_topic)
        # --- KẾT THÚC SỬA LỖI ---
        
        for _, row in exploded_df.iterrows():
            if row["client_id"] == "unknown": continue
            topic = row["topic_str"]
            src_ip = row.get("src_ip", "unknown")
            
            if not topic: continue
            if not allowed_topics_pattern.fullmatch(topic):
                key = ("unauth_topic", row["client_id"], topic)
                if should_alert(key):
                    msg = f"Unauthorized subscribe: Client {row['client_id']} ({src_ip}) subscribed to unauthorized topic '{topic}'"
                    write_alert(write_api, "unauth_topic", src_ip, row["client_id"], msg)
                    send_email("MQTT Security Alert: Unauthorized Topic", msg)

def detect_publish_flood(df, write_api):
    # Detect publish flood from a single client
    publish_df = df[df["mqtt_type"] == "publish"]
    if publish_df.empty:
        return
        
    # SỬA: Nhóm theo client_id
    flood_counts = publish_df.groupby("client_id").size().reset_index(name="count")
    for _, row in flood_counts.iterrows():
        if row["count"] > PUBLISH_FLOOD_LIMIT and row["client_id"] != "unknown":
            key = ("publish_flood", row["client_id"])
            if should_alert(key):
                src_ip = df[df["client_id"] == row["client_id"]]["src_ip"].iloc[0] if "src_ip" in df.columns else "unknown"
                msg = f"Publish flood: {row['count']} publish messages from client '{row['client_id']}' ({src_ip})"
                write_alert(write_api, "publish_flood", src_ip, row["client_id"], msg)
                send_email("MQTT Security Alert: Publish Flood", msg)

# ===================================================================
# === HÀM ĐÃ SỬA LỖI ===
# ===================================================================
def detect_topic_enumeration(df, write_api):
    # Detect topic enumeration (many unique topics from one client)
    pub_sub_df = df[df["mqtt_type"].isin(["publish", "subscribe"])]
    if pub_sub_df.empty:
        return
    
    # Logic trích xuất topic_str từ publish (đã đúng)
    pub_topics = pub_sub_df.dropna(subset=["topic"])[["client_id", "topic"]] if "topic" in pub_sub_df.columns else pd.DataFrame(columns=["client_id", "topic"])

    # --- SỬA LỖI LOGIC SUBSCRIBE ---
    sub_topics_list = []
    if "topics" in pub_sub_df.columns:
        # 1. Lấy dữ liệu subscribe và dropna, copy để tránh warning
        sub_df = pub_sub_df.dropna(subset=["topics"])[["client_id", "topics"]].copy()
        
        if not sub_df.empty:
            # 2. Hàm helper để parse chuỗi JSON (e.g., "[\"topic/a\"]") thành list (e.g., ["topic/a"])
            def parse_json_topics(json_string):
                try:
                    topics = json.loads(json_string) # json.loads giải mã chuỗi
                    if isinstance(topics, list):
                        return topics
                except Exception:
                    pass # Bỏ qua nếu JSON không hợp lệ
                return [] # Trả về list rỗng nếu lỗi

            # 3. Áp dụng hàm parse: Chuyển cột 'topics' (string) thành 'topics_list' (list)
            sub_df["topics_list"] = sub_df["topics"].apply(parse_json_topics)

            # 4. Explode trên cột 'topics_list' (list)
            exploded_df = sub_df.explode("topics_list")

            # 5. Hàm helper để trích xuất topic (vì 1 phần tử có thể là string hoặc dict)
            def get_topic(topic_entry):
                if isinstance(topic_entry, dict): 
                    return topic_entry.get("topic")
                return str(topic_entry) # Chỉ là string
            
            # 6. Trích xuất topic_str từ cột 'topics_list' đã explode
            exploded_df["topic_str"] = exploded_df["topics_list"].apply(get_topic)
            
            # 7. Thêm vào danh sách cuối cùng
            sub_topics_list.append(exploded_df[["client_id", "topic_str"]].rename(columns={"topic_str": "topic"}))
    # --- KẾT THÚC SỬA LỖI ---
    
    all_topics = pd.concat([pub_topics] + sub_topics_list).dropna(subset=["client_id", "topic"])

    if all_topics.empty:
        return
    
    # SỬA: Nhóm theo client_id 
    unique_topic_counts = all_topics.groupby("client_id")["topic"].nunique()
    
    for client_id, count in unique_topic_counts.items():
        if count > ENUM_LIMIT and client_id != "unknown": # <-- Ngưỡng đã được giảm
            key = ("topic_enumeration", client_id)
            if should_alert(key):
                src_ip = df[df["client_id"] == client_id]["src_ip"].iloc[0] if "src_ip" in df.columns else "unknown"
                msg = f"Topic enumeration: Client '{client_id}' ({src_ip}) accessed {count} unique topics"
                write_alert(write_api, "topic_enumeration", src_ip, client_id, msg)
                send_email("MQTT Security Alert: Topic Enumeration", msg)
# ===================================================================
# === KẾT THÚC HÀM SỬA LỖI ===
# ===================================================================

def detect_suspicious_client_id(df, write_api):
    # Detect suspicious client_id prefixes
    if not SUSPICIOUS_CLIENT_ID_PREFIXES:
        return
    if "client_id" not in df.columns:
        return

    unique_client_ids = df["client_id"].dropna().unique()
    for client_id in unique_client_ids:
        client_id_lower = str(client_id).lower()
        for prefix in SUSPICIOUS_CLIENT_ID_PREFIXES:
            if client_id_lower.startswith(prefix.lower()):
                key = ("suspicious_client_id", client_id)
                if should_alert(key):
                    row = df[df["client_id"] == client_id].iloc[0]
                    src_ip = row.get("src_ip", "unknown")
                    msg = f"Suspicious client_id detected: '{client_id}' matches prefix '{prefix}' from {src_ip}"
                    write_alert(write_api, "suspicious_client_id", src_ip, client_id, msg)
                    send_email("Suspicious MQTT Client ID", msg)
                break 

# --- *** RULE MỚI ĐƯỢC THÊM VÀO *** ---
def detect_brute_force(df, write_api):
    """
    Detects brute-force login attempts.
    This rule assumes failed logins are logged as 'connect' events
    with a 'return_code' == 5 (Not authorized).
    """
    if "return_code" not in df.columns:
        print("[WARN] 'return_code' column not found, skipping brute_force rule.")
        return
    
    connect_df = df[df["mqtt_type"] == "connect"].copy()
    if connect_df.empty:
        return

    # Convert return_code to numeric, errors will become NaN
    connect_df["rc_num"] = pd.to_numeric(connect_df["return_code"], errors="coerce")

    # Filter for failed authorization (return_code == 5)
    failed_auth_df = connect_df[connect_df["rc_num"] == 5]
    if failed_auth_df.empty:
        return

    # Group by source IP and count failures
    ip_fail_counts = failed_auth_df.groupby("src_ip").size().reset_index(name="count")

    for _, row in ip_fail_counts.iterrows():
        if row["count"] > BRUTE_FORCE_LIMIT and row["src_ip"] != "unknown": # <-- Ngưỡng đã được giảm
            
            key = ("brute_force", row["src_ip"])
            if should_alert(key):
                # Get the last client_id attempted from this IP for more context
                last_client_id = failed_auth_df[failed_auth_df["src_ip"] == row["src_ip"]]["client_id"].iloc[-1]
                
                msg = f"Brute force: {row['count']} failed auth attempts (rc=5) from IP '{row['src_ip']}'. Last client attempted: '{last_client_id}'"
                
                write_alert(write_api, "brute_force", row["src_ip"], last_client_id, msg)
                send_email("MQTT Security Alert: Brute Force Attack", msg)
# --- *** KẾT THÚC RULE MỚI *** ---


def normalize_columns_safely(df):
    """Ensure all expected columns exist, fill with None if not."""
    
    all_cols = [
        "src_ip", "src_port", "client_id", "mqtt_type", "topic", "payload_raw", "retain", "qos",
        "client_identifier", "bytes_toserver", "pkts_toserver", "state",
        "protocol_version", "flags_clean_session", "flags_username", "flags_password",
        "flags_will", "flags_will_retain", "topics", "dup", "message_id",
        "password", "protocol_string", "return_code", "session_present",
        "username", "qos_granted", "reason_codes"
    ]

    for col in all_cols:
        if col not in df.columns:
            df[col] = None
    
    if "client_id" in df.columns:
        df["client_id"] = df["client_id"].fillna("unknown")
    if "src_ip" in df.columns:
        df["src_ip"] = df["src_ip"].fillna("unknown")
    
    return df

def main():
    print("MQTT Rule Detect Daemon Starting...")
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    query_api = client.query_api()
    write_api = client.write_api(write_options=SYNCHRONOUS)

    try:
        health = client.health()
        print(f"[INFO] InfluxDB health: {health.status}")
    except Exception as e:
        print(f"[FATAL] Cannot connect to InfluxDB: {e}")
        return

    while True:
        try:
            # 1. Query data from InfluxDB
            print(f"[INFO] Querying data for the last {WINDOW_SECONDS} seconds...")
            
            # --- *** SỬA QUERY ĐỂ THÊM 'disconnect' CHO RULE BRUTE FORCE *** ---
            query = f"""
            from(bucket: "{SRC_BUCKET}")
              |> range(start: -{WINDOW_SECONDS}s)
              |> filter(fn: (r) => r._measurement == "mqtt_event")
              |> filter(fn: (r) => 
                  r.mqtt_type == "connect" or 
                  r.mqtt_type == "publish" or 
                  r.mqtt_type == "subscribe" or 
                  r.mqtt_type == "disconnect"
              )
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> keep(columns: [
                  "_time", "src_ip", "src_port", "client_id", "mqtt_type", "topic", "payload_raw", 
                  "retain", "qos", "client_identifier", "bytes_toserver", "pkts_toserver", 
                  "state", "protocol_version", "flags_clean_session", "flags_username", 
                  "flags_password", "flags_will", "flags_will_retain", "topics", 
                  "dup", "message_id", "password", "protocol_string", "return_code", 
                  "session_present", "username", "qos_granted", "reason_codes"
              ])
              |> sort(columns: ["_time"], desc: false)
            """

            result = query_api.query_data_frame(query=query)
            
            if isinstance(result, list):
                if not result:
                    print("[INFO] No data returned. Skipping.")
                    time.sleep(CHECK_INTERVAL)
                    continue
                df = pd.concat(result, ignore_index=True)
            else:
                df = result

            if df.empty:
                print("[INFO] No data in window. Skipping.")
                time.sleep(CHECK_INTERVAL)
                continue
            
            print(f"[INFO] Fetched {len(df)} events.")
            
            # 2. Normalize data
            df = normalize_columns_safely(df)
            
            # 2.5. Áp dụng Whitelist
            df_filtered = df 
            try:
                if WHITELISTED_CLIENT_PREFIXES:
                    mask = df['client_id'].apply(
                        lambda x: any(str(x).startswith(prefix) for prefix in WHITELISTED_CLIENT_PREFIXES)
                    )
                    df_filtered = df[~mask] 
                
                print(f"[INFO] Original events: {len(df)}, Filtered events (after whitelist): {len(df_filtered)}")

                if df_filtered.empty:
                    print("[INFO] All events in window were whitelisted. Skipping rules.")
                    time.sleep(CHECK_INTERVAL)
                    continue
            
            except Exception as e:
                print(f"[ERROR] Failed to apply whitelist: {e}")
                df_filtered = df 
            
            # 3. Run detection rules
            
            try:
                detect_duplicate_client_id(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] duplicate_client_id: {e}")

            try:
                detect_reconnect_storm(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] reconnect_storm: {e}")

            try:
                detect_wildcard_abuse(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] wildcard_abuse: {e}")

            try:
                detect_retain_qos_abuse(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] retain_qos_abuse: {e}")

            try:
                detect_payload_anomaly(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] payload_anomaly: {e}")

            try:
                detect_unauthorized_topics(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] unauthorized_topics: {e}")

            try:
                detect_publish_flood(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] publish_flood: {e}")
                
            try:
                detect_topic_enumeration(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] topic_enumeration: {e}")
            
            try:
                detect_suspicious_client_id(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] suspicious_client_id: {e}")

            # --- *** THÊM LỆNH GỌI RULE MỚI *** ---
            try:
                detect_brute_force(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] brute_force: {e}")
            # --- *** KẾT THÚC *** ---

        except Exception as e:
            print(f"[ERROR] Query/Detect: {e}")
            time.sleep(CHECK_INTERVAL)
            continue

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()