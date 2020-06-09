from flask import Flask
from flask import render_template, Response
from flask import jsonify
from flask import request
from datetime import datetime
import collections
import logging
import time
import json
import os

from Flask_Gui.log_database import Logger
from Core.rekall_analyser import *
from Core.sleuthkit_analyser import *
from Core.worker import execute_command
from Utils.config_loader import Config


"""
" Flask_Gui/index.py
" The Flask app shows a GUI to communicate with the monitor and analyse data local.
"""

app = Flask(__name__)

rekall_analyser = RekallAnalyser()
sleuthkit_analyser = SleuthKitAnalyser()
logger = Logger()
kafka_client = None
current_partitions = None

def init(kc):
    global kafka_client
    kafka_client = kc

def consume_data():
    """ Receives the Kafka data.
        If cmd is 'get_memory_dump' it triggers sftp.
        If cmd is 'get_partitions' it saves partition information for later use.
    """
    global current_partitions
    # Load current log if exists
    current_log = logger.read_current()
    yield "\n".join(current_log)

    while 1:
        data = kafka_client.get_data()
        if len(data) != 0:
            msg = data.value.decode("utf-8")
            jsn = json.loads(msg)

            # if we get an answer from the memory dump command, we start sftp to local
            if jsn["command"][0] == "get_memory_dump" and jsn["type"] == "data":
                filename = os.path.basename(jsn["content"]["path"])
                output_path = os.path.join(Config.memory_dump_path(), filename)
                cmd = ["sftp_file", jsn["content"]["path"], output_path]
                command = {"analyser":None, "command":cmd}
                execute_command(command, None, kafka_client=kafka_client)

            # if we get an answer from get partitions we refresh our list to show it in gui
            if jsn["command"][0] == "get_partitions" and jsn["type"] == "data":
                current_partitions = {}
                for p in  jsn["content"]["objects"]:
                    name = jsn["content"]["objects"][p]["description"]
                    offset = jsn["content"]["objects"][p]["offset"]
                    current_partitions[name] = offset

            res = json.dumps(jsn, indent=4, sort_keys=True)
            yield res + "\n"
            logger.write(res)
        time.sleep(0.1)


@app.template_filter('fromtimestamp')
def from_timestamp(value):
    """ Jinja Filter """
    return datetime.fromtimestamp(value)

@app.route("/")
def index():
    """ The index page """
    kafka_client.__init__()
    logs = logger.list_logs()
    vms = Config.all_vms()
    return render_template('index.html',
            title='Welcome',
            current_rekall_dump=rekall_analyser.get_dump_name(),
            current_sleuthkit_dump=sleuthkit_analyser.get_dump_name(),
            vms=vms,
            logs=logs)


@app.route("/stream_kafka")
def stream_kafka():
    """ The data stream which showes up on the index page """
    return Response(consume_data(), content_type='application/json')


@app.route("/cmd", methods=['POST'])
def command():
    """ Call cmd to execute a command.
        Send the command over kafka to the monitor or exdcute local.
        POST json {"mode":<acquisition, analysis>,
          "command":[args],
          "analyser":<rekall, sleuthkit>}
    """ 
    mode = request.json['mode']
    cmd = request.json['command']
    analyser = request.json['analyser']
    command = {"analyser":analyser, "command":cmd}
    if mode == "acquisition": # For monitor
        kafka_client.send_command(command)
        return "executed command %s" % cmd
    if mode == "analysis": # Local
        if analyser == "rekall":
            execute_command(command, rekall_analyser, kafka_client=kafka_client)
            return "executed command %s" % cmd
        if analyser == "sleuthkit":
            execute_command(command, sleuthkit_analyser, kafka_client=kafka_client)
            return "executed command %s" % cmd


@app.route("/dumps/list")
def list_dumps_memory():
    """ Returns all the dumps as json """
    memory_dumps = os.listdir(Config.memory_dump_path())
    storage_dumps = os.listdir(Config.storage_dump_path())
    dumps = {"memory": memory_dumps, "storage": storage_dumps}
    return jsonify(dumps)

@app.route("/partitions")
def partitions():
    """ Lists the partitions of the current image """
    return jsonify(current_partitions)


@app.route("/log/get/<id>")
def get_log(id):
    """ Return text of log """
    log_text = logger.read_all(id)
    res = "\n".join(log_text)
    return Response(res, mimetype='text/plain')

@app.route("/log/remove/<id>")
def remove_log(id):
    """ Remove log with the id """
    log_text = logger.remove(id)
    return "ok"

@app.route("/log/reset")
def reset_log():
    """ Reset logger and the analysers for a new session """
    logger.reset()
    sleuthkit_analyser.reset()
    rekall_analyser.reset()
    return "ok"
