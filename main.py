import argparse
import logging
import json
import sys

from Utils.kafka_client import KafkaClient
from Core.rekall_analyser import *
from Core.sleuthkit_analyser import *
from Core.worker import *
from Utils.stix_generator import *
from Flask_Gui import index
from Utils.config_loader import Config

"""
" main.py
" The main function starts wether the monitor or the workstation part of the program.
"""

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cmd", help="executes only CMD. Ignores mode.")
    parser.add_argument("--mode", help="choose the mode", default="monitor",
                        choices=["monitor", "workstation"])    
    args = parser.parse_args()

    if args.cmd:
        rekall_analyser = RekallAnalyser(vm="ubuntu1604",
                               profile="/home/fhantke/profile/4.4.0-112-generic")
        execute_command([args.cmd], rekall_analyser)
        # sk = SleuthKitAnalyser(path="/data/dforensics/storage_dumps/disk0")
        # print(json.dumps(sk.get_partitions(), indent=4))
        # print(json.dumps(sk.get_filesystem(1048576), indent=4))
        # print(json.dumps(sk.list_dir("/home/fhantke"), indent=4))

        sys.exit(0)

    kk_client = KafkaClient()

    if args.mode == "monitor":
        # The monitor receives commands via kafka to execute them
        vm = Config.all_vms()[0]
        profile = os.path.join(Config.rekall_profile_repository_path(), vm["profile"])
        rekall_analyser = RekallAnalyser(vm=vm["name"], profile=profile)
        while True:
            data = kk_client.get_command()
            if len(data) == 0:
                continue
            logging.info('Received data: {}'.format(data))
            msg = data.value.decode("utf-8")
            jsn = json.loads(msg)
            execute_command(jsn, analyser=rekall_analyser, kafka_client=kk_client)
    elif args.mode == "workstation":
        # The workstation starts a Flask app in which one can send commands to the monitor
        # or analyse local data
        index.init(kk_client)
        index.app.run(host="0.0.0.0")
