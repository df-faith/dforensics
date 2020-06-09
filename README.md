DForensics
==========

DForensics is the forensics part of the [DINGfest](https://dingfest.ur.de/) project.
Through the use of [Rekall](http://www.rekall-forensic.com/) and [Sleuthkit](https://www.sleuthkit.org/), an analyst can perform investigations on a Xen VM from his local workstation.
The communication works via [Kafka](https://kafka.apache.org/intro) as it is part of the whole project.

Setup
-------------

 * Setup a venv with all requirements.
   `apt-get install python3 virtualenv python3-dev libssl-dev libncurses5-dev`
   `pip install kafka-python stix2 setuptools wheel rekall-agent rekall filemagic libqcow-python pysftp flask`
 * Edit config.json
 * Run `main.py --mode monitor` on your monitor machine on which DOM0 runs
 * Run `main.py --mode workstation` on your local PC which can talk to DOM0 via Kafka

Usage
-------------
When the monitor is setup and running we can use our workstation to analyse the VMs.
`main.py --mode workstation` starts the workstation and we can reach it on localhost:5000.
We should first acquire copies of data to work with.
This can be done with memdump and subsequently, we can analyse the dumps in the analysis mode.

Kafka
-------------
* **commands topic** - Send commands over this channel in the format of:
  `{"analyser":"(sleuthkit | rekall)", "command":["(get_dump | get_ifconfig | ...)", [arg1], ...]}`
* **data topic** - Send the result of the command over this channel. This includes error messages. The data is in the format of:
  `{"type": "(data | error)", "command":["(get_dump | get_ifconfig | ...)", [arg1], ...], "contetn":"content as string or json"}`

Config.json
-------------
You need to configurate the program first.
For this purpose, please change the standard values in config.json
 * **memory_dump_path** - The path where memory dumps are stored
 * **storage_dump_path** - The path where disk images copies are stored
 * **log_database_path** - The path where logs of analysis session are stored
 * **rekall_profile_repository_path** - The path where rekall profiles are stored
 * **monitor_ip** - The ip of the hypervisor
 * **monitor_ssh_user** - The ssh user of the hypervisor
 * **monitur_ssh_pw** - The ssh password of the ssh user
 * **kafka_host** - The ip of Kafka
 * **kafka_port** - The port of Kafka
 * **kafka_topic_commands** - The Kafka topic which should be used to send commands
 * **kafka_topic_data** - The Kafka topic which is used to send data/answers
