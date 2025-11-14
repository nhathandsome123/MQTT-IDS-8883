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
import math
from collections import Counter

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
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
PAYLOAD_LIMIT = int(os.getenv("PAYLOAD_LIMIT", "1024"))
RETAIN_QOS_LIMIT = int(os.getenv("RETAIN_QOS_LIMIT", "5"))
RECONNECT_LIMIT = int(os.getenv("RECONNECT_LIMIT", "10"))
PUBLISH_FLOOD_LIMIT = int(os.getenv("PUBLISH_FLOOD_LIMIT", "100"))
PAYLOAD_ATTACK_THRESHOLD = int(os.getenv("PAYLOAD_ATTACK_THRESHOLD", "5000"))

# --- Ngưỡng đã giảm theo yêu cầu ---
ENUM_LIMIT = int(os.getenv("ENUM_LIMIT", "10")) # Giảm từ 20 xuống 10
BRUTE_FORCE_LIMIT = int(os.getenv("BRUTE_FORCE_LIMIT", "5")) # Thêm mới, ngưỡng 5

ALERT_COOLDOWN = int(os.getenv("ALERT_COOLDOWN", "60")) # 1 phút

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
    "truongphong_office_sub", "truongphong_energy_sub", "truongphong_production_sub",
    "truongphong_storage_sub", "truongphong_security_sub"
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

# --- Đã xóa src_ip khỏi hàm write_alert ---
def write_alert(write_api, rule_name, client_id, message):
    """Write an alert to the InfluxDB alert bucket."""
    point = Point("mqtt_alert") \
        .tag("rule", rule_name) \
        .tag("client_id", str(client_id)) \
        .field("message", str(message)) \
        .time(datetime.utcnow(), WritePrecision.NS)
    
    write_api.write(bucket=ALERT_BUCKET, org=INFLUX_ORG, record=point)
    print(f"[ALERT] Rule: {rule_name} | Client: {client_id} | Msg: {message}")


# --- Rule Functions (Không bị ảnh hưởng) ---

# def detect_duplicate_client_id(df, write_api):
#     connect_df = df[df["mqtt_type"] == "connect"].copy()
#     if connect_df.empty:
#         return
        
#     client_ports = connect_df.groupby("client_id")["src_port"].nunique()
#     duplicates = client_ports[client_ports > 1] 
    
#     for client_id, port_count in duplicates.items():
#         if not client_id or client_id == "unknown":
#             continue
        
#         key = ("duplicate_client_id", client_id)
#         if should_alert(key):
#             msg = f"Duplicate client_id: '{client_id}' seen using {port_count} different source ports."
#             write_alert(write_api, "duplicate_client_id", client_id, msg)
#             send_email("MQTT Security Alert: Duplicate Client ID", msg)

def detect_reconnect_storm(df, write_api):
    connect_events = df[df["mqtt_type"].isin(["connect", "disconnect"])].copy()
    if connect_events.empty:
        return

    # ⚠️ Bỏ qua các client có alert payload trước đó
    if "payload_len" in df.columns:
        oversized_clients = set(df.loc[df["payload_len"] > PAYLOAD_ATTACK_THRESHOLD, "client_id"].dropna())
        connect_events = connect_events[~connect_events["client_id"].isin(oversized_clients)]

    storm_counts = connect_events.groupby("client_id").size().reset_index(name="count")
    for _, row in storm_counts.iterrows():
        if row["count"] > RECONNECT_LIMIT and row["client_id"] != "unknown":
            key = ("reconnect_storm", row["client_id"]) 
            if should_alert(key):
                msg = f"Reconnect storm: {row['count']} connect/disconnect events from client '{row['client_id']}'"
                write_alert(write_api, "reconnect_storm", row["client_id"], msg)
                send_email("MQTT Security Alert: Reconnect Storm", msg)


def detect_retain_qos_abuse(df, write_api):
    publish_df = df[df["mqtt_type"] == "publish"].copy()
    if publish_df.empty:
        return

    publish_df["qos_num"] = pd.to_numeric(publish_df["qos"], errors="coerce")
    publish_df["retain_bool"] = pd.to_numeric(publish_df["retain"], errors="coerce").fillna(0).astype(bool)

    abuse_df = publish_df[(publish_df["retain_bool"] == True) | (publish_df["qos_num"] > 0)]
    
    abuse_counts = abuse_df.groupby("client_id").size().reset_index(name="count")
    for _, row in abuse_counts.iterrows():
        if row["count"] > RETAIN_QOS_LIMIT and row["client_id"] != "unknown":
            
            key = ("retain_qos_abuse", row["client_id"])
            if should_alert(key):
                msg = f"Retain/QoS abuse: {row['count']} messages with Retain=True and QoS>0 from client '{row['client_id']}'"
                write_alert(write_api, "retain_qos_abuse", row["client_id"], msg)
                send_email("MQTT Security Alert: Retain/QoS Abuse", msg)


def detect_payload_flow_anomaly(df, write_api):
    """
    Rule – Payload Oversize Detection (Simplified)
    Phát hiện các bản tin MQTT có payload_len vượt ngưỡng cho phép.
    Loại bỏ hoàn toàn các phép tính entropy và tổng byte để tránh cảnh báo giả.
    """
    publish_df = df[df["mqtt_type"] == "publish"].copy()
    if publish_df.empty:
        return

    # Đảm bảo cột payload_len tồn tại và là số
    if "payload_len" not in publish_df.columns:
        publish_df["payload_len"] = publish_df["payload_raw"].astype(str).apply(
            lambda s: len(s.encode("utf-8")) if isinstance(s, str) else 0
        )
    publish_df["payload_len"] = pd.to_numeric(publish_df["payload_len"], errors="coerce").fillna(0).astype(int)

    # Lặp qua từng bản tin và kiểm tra ngưỡng
    for _, row in publish_df.iterrows():
        cid = row.get("client_id", "unknown")
        if cid == "unknown":
            continue
        topic = row.get("topic", "")
        plen = int(row.get("payload_len", 0))

        if plen > PAYLOAD_ATTACK_THRESHOLD:
            key = ("publish_payload_large", cid)
            if should_alert(key):
                msg = f"Oversized payload detected: {plen} bytes from client '{cid}' on topic '{topic}' (threshold={PAYLOAD_ATTACK_THRESHOLD})"
                write_alert(write_api, "publish_payload_large", cid, msg)
                send_email("MQTT Security Alert: Oversized Payload", msg)

def detect_publish_flood(df, write_api):
    """
    Rule 4 – Publish Flood (Cải tiến)
    Phát hiện client gửi quá nhiều bản tin publish hoặc tổng dung lượng payload lớn bất thường.
    """
    publish_df = df[df["mqtt_type"] == "publish"].copy()
    if publish_df.empty:
        return

    # Bổ sung: tính độ dài payload nếu chưa có
    if "payload_len" not in publish_df.columns:
        publish_df["payload_len"] = publish_df["payload_raw"].astype(str).apply(len)
    else:
        publish_df["payload_len"] = pd.to_numeric(publish_df["payload_len"], errors="coerce").fillna(0)

    # Gộp theo client_id
    agg_df = publish_df.groupby("client_id").agg(
        message_count=("mqtt_type", "count"),
        total_bytes=("payload_len", "sum")
    ).reset_index()

    for _, row in agg_df.iterrows():
        cid = row["client_id"]
        if cid == "unknown":
            continue
        
        msg_count = int(row["message_count"])
        total_bytes = int(row["total_bytes"])

        # Ngưỡng cảnh báo (có thể tinh chỉnh)
        msg_limit = PUBLISH_FLOOD_LIMIT
        byte_limit = PUBLISH_FLOOD_LIMIT * 5000  # ví dụ: 100 messages ≈ 500 KB

        if msg_count > msg_limit or total_bytes > byte_limit:
            key = ("publish_flood", cid)
            if should_alert(key):
                msg = (
                    f"Publish flood detected: client '{cid}' sent {msg_count} publish messages "
                    f"totaling {total_bytes} bytes in the last window."
                )
                write_alert(write_api, "publish_flood", cid, msg)
                send_email("MQTT Security Alert: Publish Flood", msg)
                print(f"[ALERT] Rule: publish_flood | Client: {cid} | Msgs: {msg_count} | Bytes: {total_bytes}")


def detect_suspicious_client_id(df, write_api):
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
                    msg = f"Suspicious client_id detected: '{client_id}' matches prefix '{prefix}'"
                    write_alert(write_api, "suspicious_client_id", client_id, msg)
                    send_email("Suspicious MQTT Client ID", msg)
                break 


def detect_brute_force(df, write_api):
    """
    Rule - Brute Force Detection (Logic 'return_code' CHUẨN)
    Phát hiện bằng cách lọc các sự kiện 'connect' (vì forwarder đã gộp)
    có 'return_code' là 4 (Bad username/password) hoặc 5 (Not authorized).
    """
    
    # Lọc các sự kiện 'connect'
    # File chuẩn hóa của chúng ta đặt mqtt_type="connect"
    # và gộp cả trường 'return_code' vào đó
    connect_df = df[df["mqtt_type"] == "connect"].copy()
    if connect_df.empty:
        return

    # Đảm bảo return_code là số
    connect_df["return_code_num"] = pd.to_numeric(connect_df["return_code"], errors="coerce")

    # Lọc các lần đăng nhập thất bại CÓ return_code
    # RC 4 = Bad username or password
    # RC 5 = Not authorized
    failed_logins = connect_df[
        connect_df["return_code_num"].isin([4, 5]) &
        connect_df["username"].notna() &
        (connect_df["username"] != "") &
        (connect_df["username"] != "unknown")
    ]

    if failed_logins.empty:
        # print("[DBG] brute_force: No failed login (RC 4/5) events with username found.")
        return

    # Đếm số lần thất bại cho mỗi username
    failure_counts = failed_logins.groupby("username").size().reset_index(name="count")
    print(f"[DBG] brute_force: Found failure counts: {failure_counts.to_dict('records')}")

    # Kiểm tra ngưỡng (BRUTE_FORCE_LIMIT = 5)
    for _, row in failure_counts.iterrows():
        username = row["username"]
        count = int(row["count"])
        
        if count > BRUTE_FORCE_LIMIT:
            key = ("brute_force", username)
            if should_alert(key):
                msg = (
                    f"Brute force detected: {count} failed login attempts (RC 4/5) "
                    f"for username '{username}' (threshold={BRUTE_FORCE_LIMIT})"
                )
                
                # Lấy client_id cuối cùng của kẻ tấn công để ghi log (chính xác hơn)
                attacker_client_id = failed_logins[failed_logins["username"] == username]["client_id"].iloc[-1]
                
                write_alert(write_api, "brute_force", attacker_client_id, msg) 
                send_email("MQTT Security Alert: Brute Force", msg)
                print(f"[ALERT] Rule: brute_force | Username: {username} | Failed Attempts: {count}")
            else:
                print(f"[DBG] brute_force: Alert for {username} skipped (cooldown).")



def detect_wildcard_abuse(df, write_api):
    """
    (ĐÃ VIẾT LẠI)
    Phát hiện lạm dụng wildcard.
    Rule này giờ đây đọc trực tiếp trường 'topic' từ các sự kiện 'subscribe'.
    """
    # Lấy các sự kiện subscribe CÓ chứa trường 'topic' (đã được chuẩn hóa)
    subscribe_df = df[
        (df["mqtt_type"] == "subscribe") &
        (df["topic"].notna())
    ].copy()

    if subscribe_df.empty:
        return

    # Tìm các topic chứa '#' hoặc '+' trực tiếp trong cột 'topic'
    wildcard_abuse_df = subscribe_df[subscribe_df["topic"].str.contains(r"#|.*\+.*", na=False)]
    
    # Lặp qua các vi phạm
    for _, row in wildcard_abuse_df.iterrows():
        topic = row["topic"]
        client_id = row["client_id"]
        
        key = ("wildcard_abuse", client_id, topic)
        if should_alert(key):
            msg = f"Wildcard abuse: Client {client_id} subscribed to '{topic}'"
            write_alert(write_api, "wildcard_abuse", client_id, msg)
            send_email("MQTT Security Alert: Wildcard Abuse", msg)

def detect_unauthorized_topics(df, write_api):
    """
    (ĐÃ VIẾT LẠI)
    Phát hiện truy cập topic không được phép (publish và subscribe).
    Rule này giờ đây đọc trực tiếp trường 'topic' cho CẢ HAI sự kiện.
    """
    if not ALLOWED_TOPICS_REGEX:
        return
    
    # Biên dịch 1 lần
    allowed_topics_pattern = re.compile("|".join(f"({r})" for r in ALLOWED_TOPICS_REGEX))

    # Lấy TẤT CẢ sự kiện (publish HOẶC subscribe) CÓ chứa trường 'topic'
    df_with_topic = df[
        df["mqtt_type"].isin(["publish", "subscribe"]) &
        df["topic"].notna()
    ].copy()

    if df_with_topic.empty:
        return

    # Thêm một cột 'is_allowed' để kiểm tra regex
    # (Vector hóa nhanh hơn là lặp)
    df_with_topic["is_allowed"] = df_with_topic["topic"].apply(
        lambda t: bool(allowed_topics_pattern.fullmatch(t))
    )
    
    # Lọc ra những sự kiện không được phép
    unauth_df = df_with_topic[df_with_topic["is_allowed"] == False]

    # Lặp qua các vi phạm
    for _, row in unauth_df.iterrows():
        if row["client_id"] == "unknown": continue
        
        topic = row["topic"]
        client_id = row["client_id"]
        mqtt_type = row["mqtt_type"]
        
        key = ("unauth_topic", client_id, topic)
        if should_alert(key):
            msg = f"Unauthorized {mqtt_type}: Client {client_id} tried to access unauthorized topic '{topic}'"
            write_alert(write_api, "unauth_topic", client_id, msg)
            send_email("MQTT Security Alert: Unauthorized Topic", msg)

def detect_topic_enumeration(df, write_api):
    """
    (ĐÃ VIẾT LẠI)
    Phát hiện dò quét topic (publish và subscribe).
    Rule này giờ đây đọc trực tiếp trường 'topic' cho CẢ HAI sự kiện.
    """
    # Lấy TẤT CẢ sự kiện (publish HOẶC subscribe) CÓ chứa trường 'topic'
    all_topics_df = df[
        df["mqtt_type"].isin(["publish", "subscribe"]) &
        df["topic"].notna()
    ].copy()

    if all_topics_df.empty:
        return
    
    # Nhóm theo client_id và đếm số topic DUY NHẤT
    unique_topic_counts = all_topics_df.groupby("client_id")["topic"].nunique()
    
    for client_id, count in unique_topic_counts.items():
        # Kiểm tra với ENUM_LIMIT (đã giảm xuống 10)
        if count > ENUM_LIMIT and client_id != "unknown": 
            key = ("topic_enumeration", client_id)
            if should_alert(key):
                msg = f"Topic enumeration: Client '{client_id}' accessed {count} unique topics"
                write_alert(write_api, "topic_enumeration", client_id, msg)
                send_email("MQTT Security Alert: Topic Enumeration", msg)

# ===================================================================
# === KẾT THÚC PHẦN VIẾT LẠI ===
# ===================================================================


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
            
            # Query này vẫn đúng vì nó lấy _measurement == "mqtt_event"
            # và file log mới của bạn vẫn ghi vào "mqtt_event"
            query = f"""
            from(bucket: "{SRC_BUCKET}")
              |> range(start: -{WINDOW_SECONDS}s)
              |> filter(fn: (r) => r._measurement == "mqtt_event")
              |> filter(fn: (r) => 
                  r.mqtt_type == "connect" or 
                  r.mqtt_type == "publish" or 
                  r.mqtt_type == "subscribe" or 
                  r.mqtt_type == "disconnect" or
                  r.mqtt_type == "connack" 
              )
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> keep(columns: [
                  "_time", "src_ip", "src_port", "client_id", "mqtt_type", "topic", "payload_raw", "payload_len",
                  "retain", "qos", "client_identifier", "bytes_toserver", "pkts_toserver", 
                  "state", "protocol_version", "flags_clean_session", "flags_username", 
                  "flags_password", "flags_will", "flags_will_retain", "topics", 
                  "dup", "message_id", "password", "protocol_string", "return_code", 
                  "session_present", "username", "qos_granted", "reason_codes"
              ])
              |> sort(columns: ["_time"], desc: false)
            """
            
            # (Ghi chú nhỏ: Tôi đã thêm 'connack' vào query để đảm bảo nó luôn được lấy)
            # (Trong file gốc của bạn, 'connack' bị thiếu, nhưng có thể nó vẫn chạy 
            # do một query khác, tuy nhiên thêm vào đây sẽ chắc chắn hơn)
            if 'r.mqtt_type == "connack"' not in query:
                 query = query.replace(
                     'r.mqtt_type == "disconnect"',
                     'r.mqtt_type == "disconnect" or r.mqtt_type == "connack"'
                 )


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
                detect_wildcard_abuse(df_filtered, write_api) # (Đã được viết lại)
            except Exception as e:
                print(f"[RULE ERROR] wildcard_abuse: {e}")

            try:
                detect_retain_qos_abuse(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] retain_qos_abuse: {e}")

            try:
                detect_payload_flow_anomaly(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] payload_anomaly: {e}")

            try:
                detect_unauthorized_topics(df_filtered, write_api) # (Đã được viết lại)
            except Exception as e:
                print(f"[RULE ERROR] unauthorized_topics: {e}")

            try:
                detect_publish_flood(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] publish_flood: {e}")
                
            try:
                detect_topic_enumeration(df_filtered, write_api) # (Đã được viết lại)
            except Exception as e:
                print(f"[RULE ERROR] topic_enumeration: {e}")
            
            try:
                detect_suspicious_client_id(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] suspicious_client_id: {e}")

            try:
                detect_brute_force(df_filtered, write_api) # (ĐÃ SỬA)
            except Exception as e:
                print(f"[RULE ERROR] brute_force: {e}")

        except Exception as e:
            print(f"[ERROR] Query/Detect: {e}")
            time.sleep(CHECK_INTERVAL)
            continue

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
