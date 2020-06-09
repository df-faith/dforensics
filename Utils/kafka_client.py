from kafka import KafkaConsumer
from kafka import KafkaProducer
from stix2 import ObservedData
import logging
import json

from Utils.config_loader import Config

"""
" Utils/kafka_client.py
" The KafkaClient class is used to setup the communication with Kafka.
"""

logging.basicConfig(level=logging.INFO)

class KafkaClient():
    host = Config.kafka_host()
    port = Config.kafka_port()
    topic_commands = Config.kafka_topic_commands()
    topic_data = Config.kafka_topic_data()
    
    def __init__(self):
        self.command_consumer = KafkaConsumer(
                bootstrap_servers=[(('%s:%s') % (self.host, self.port))],
                consumer_timeout_ms=100)
        self.command_consumer.subscribe(self.topic_commands)
        self.data_consumer = KafkaConsumer(
                bootstrap_servers=[(('%s:%s') % (self.host, self.port))],
                consumer_timeout_ms=100)
        self.data_consumer.subscribe(self.topic_data)
        self.producer = KafkaProducer(bootstrap_servers=[(('%s:%s') % (self.host, self.port))])

    def get_command(self): 
        msg = next(self.command_consumer, "")
        return msg

    def send_command(self, msg):
        if isinstance(msg, str):
            self.producer.send(self.topic_commands, msg.encode())
        elif isinstance(msg, dict):
            self.producer.send(self.topic_commands, json.dumps(msg).encode())

    def get_data(self):
        msg = next(self.data_consumer, "")
        return msg

    def send_data(self, msg): 
        if isinstance(msg, str):
            self.producer.send(self.topic_data, msg.encode())
        elif isinstance(msg, dict):
            self.producer.send(self.topic_data, json.dumps(msg).encode())
        elif isinstance(msg, ObservedData):
            self.producer.send(self.topic_data, msg.serialize().encode())

    def get_topic_commands(self):
        return self.topic_commands

    def get_topic_data(self):
        return self.topic_data
