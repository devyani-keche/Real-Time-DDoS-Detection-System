import findspark
findspark.init()

import logging
from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from pyspark.sql.types import *

logging.getLogger('cassandra').setLevel(logging.ERROR)

print("🔥 Booting up Apache Spark Engine...")
spark = SparkSession.builder \
    .appName("RealTimeCyberDefense") \
    .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0,com.datastax.spark:spark-cassandra-connector_2.12:3.4.1") \
    .config("spark.cassandra.connection.host", "127.0.0.1") \
    .config("spark.cassandra.connection.port", "9042") \
    .master("local[*]") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

schema = StructType([
    StructField("timestamp", StringType()), StructField("ip_address", StringType()),
    StructField("http_method", StringType()), StructField("endpoint", StringType()),
    StructField("status_code", IntegerType()), StructField("bytes", IntegerType()),
    StructField("user_agent", StringType())
])

kafka_stream = spark.readStream.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("subscribe", "web-logs").load()
parsed_df = kafka_stream.select(from_json(col("value").cast("string"), schema).alias("data")).select("data.*")
time_df = parsed_df.withColumn("event_time", to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"))

windowed_df = time_df.withWatermark("event_time", "15 seconds") \
    .groupBy(window("event_time", "10 seconds", "5 seconds"), "ip_address") \
    .agg(count("*").alias("request_count"), sum(when(col("status_code").isin(401, 403, 404, 429, 500), 1).otherwise(0)).alias("error_count"))

attackers_df = windowed_df.filter((col("request_count") > 150) | (col("error_count") > 100))

final_df = attackers_df.withColumn("reason",
    when(col("request_count") > 150, concat(lit("DDoS: "), col("request_count"), lit(" req in 10s")))
    .otherwise(concat(lit("Brute-force: "), col("error_count"), lit(" errors in 10s")))
).select(col("ip_address"), col("window.start").cast("string").alias("window_start"), col("request_count"), col("reason"))

def write_to_cassandra(batch_df, batch_id):
    batch_df.write.format("org.apache.spark.sql.cassandra").options(table="blocked_ips", keyspace="cyber_defense").mode("append").save()

print("⚡ Spark is running! Analyzing traffic and writing threats to Cassandra...")
print("Press Ctrl+C to stop.")

query = final_df.writeStream.outputMode("update").foreachBatch(write_to_cassandra).start()
query.awaitTermination()