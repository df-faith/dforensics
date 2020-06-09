import os
import json

"""
" Utils/config_loader.py
" The Config class is used to load the config variables.
"""

class Config:
    """ Interact with configuration variables."""

    with open(os.path.join(os.getcwd(), 'config.json')) as f:
        config = json.load(f)

    @classmethod
    def all_vms(self):
        return self.config['vms']

    @classmethod
    def rekall_profile_repository_path(self):
        return self.config['rekall_profile_repository_path']

    @classmethod
    def memory_dump_path(self):
        return self.config['memory_dump_path']
 
    @classmethod
    def storage_dump_path(self):
        return self.config['storage_dump_path']
 
    @classmethod
    def monitor_ip(self):
        return self.config['monitor_ip']
 
    @classmethod
    def monitor_ssh_user(self):
        return self.config['monitor_ssh_user']
 
    @classmethod
    def monitor_ssh_pw(self):
        return self.config['monitor_ssh_pw']
 
    @classmethod
    def monitor_ssh_key(self):
        return self.config['monitor_ssh_key']

    @classmethod
    def monitor_ssh_key_pass(self):
        return self.config['monitor_ssh_key_pass']
 
    @classmethod
    def kafka_host(self):
        return self.config['kafka_host']
 
    @classmethod
    def kafka_port(self):
        return self.config['kafka_port']
 
    @classmethod
    def kafka_topic_commands(self):
        return self.config['kafka_topic_commands']
 
    @classmethod
    def kafka_topic_data(self):
        return self.config['kafka_topic_data']
 
    @classmethod
    def log_database_path(self):
        return self.config['log_database_path']
