import pandas as pd
import json
import time
from kafka import KafkaProducer
from cassandra.cluster import Cluster

print("🔗 Attempting to connect to local Cassandra...")

# ==========================================
# ENTERPRISE RETRY LOGIC
# ==========================================
connected = False
retries = 0
while not connected and retries < 15:
    try:
        cluster = Cluster(['127.0.0.1'], port=9042)
        session = cluster.connect()
        connected = True
        print("✅ Successfully connected to Cassandra!")
    except Exception as e:
        print(f"⏳ Cassandra is still booting up... Waiting 15 seconds (Attempt {retries+1}/15)")
        time.sleep(15)
        retries += 1

if not connected:
    print("❌ Could not connect to Cassandra after 3 minutes. Check Docker Desktop!")
    exit(1)
# ==========================================

session.execute("CREATE KEYSPACE IF NOT EXISTS cyber_defense WITH replication = {'class':'SimpleStrategy', 'replication_factor':1};")
session.execute("""
    CREATE TABLE IF NOT EXISTS cyber_defense.blocked_ips (
        ip_address text, window_start timestamp, window_end timestamp,
        request_count int, reason text, PRIMARY KEY (ip_address, window_start)
    );
""")
print("✅ Cassandra Keyspace and Table ready!")

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

print("🚀 Streaming CSV to Kafka topic 'web-logs'...")
df = pd.read_csv("advanced_web_logs.csv")

from datetime import datetime

import random

count = 0
for _, row in df.iterrows():
    data_dict = row.to_dict()
    # Mask the historical timestamp with the current true time for a realistic livestream demo
    data_dict["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
    
    producer.send("web-logs", data_dict)
    count += 1
    
    # Inject a realistic burst every 400 normal background logs (approx every 4 seconds)
    if count % 400 == 0:
        attack_type = random.choice(["DDOS", "BRUTEFORCE"])
        bad_ip = f"{random.randint(11, 240)}.{random.randint(11, 240)}.{random.randint(11, 240)}.{random.randint(11, 240)}"
        print(f"⚠️ [MOCK THREAT] Initiating {attack_type} payload from {bad_ip}...")
        
        burst_size = random.randint(180, 500)
        for _ in range(burst_size):
            attack_dict = data_dict.copy()
            attack_dict["ip_address"] = bad_ip
            attack_dict["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
            
            # Simulate the attack signature
            if attack_type == "DDOS":
                attack_dict["status_code"] = 200
            else:
                attack_dict["status_code"] = 401
                
            producer.send("web-logs", attack_dict)
        print(f"💥 Payload injected! ({burst_size} malicious requests)")
    
    # Small delay so it simulates a live website instead of dumping all at once
    time.sleep(0.01) 
    
producer.flush()
print(f"✅ Finished! Sent {count:,} logs to Kafka.")