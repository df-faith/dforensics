import pysftp
from Utils.stix_generator import *
from Core.rekall_analyser import *
from Core.sleuthkit_analyser import *
import os

"""
" Core/worker.py
" Woker provides the execute command method.
" That is used to call the various analyser and return the data
" in the correct format to display in the webtool.
"""

def execute_command(command, analyser, kafka_client=None):
    """ Take a command and analyser and execute command.
    Subsequently, send it via kafka or log.
    - command dict: contains the command and the analyser name
    - analyser: Wether RekallAnalyser or SleuthKitAnalyser 
    - return: The result of the command
    """

    def forge_data(d, generator=None):
        """ forge data packet out of result """
        if type(d) is dict and "error" in d:
            return {"type":"error", "command":command["command"], "content":d["error"]}
        if type(d) is tuple and "error" in d[0]:
            return {"type":"error", "command":command["command"], "content":d[0]["error"]}
        if generator is not None:
            d = generator(d, as_json=True)
        return {"type":"data", "command":command["command"], "content":d}

    logging.info("execute command: %s" % command["command"])
    anly = command["analyser"]
    cmd = command["command"][0]
    args = command["command"][1:]
    data = None

    # Send command to corresponding analyser and forge data packet
    if anly == "rekall":
        if not isinstance(analyser, RekallAnalyser):
            data = forge_data({"error":"Your analyser doesn't match your use"})
        elif cmd == "change_dump":
            path = os.path.join(Config.memory_dump_path(), args[0])
            vm_configs = Config.all_vms()
            vm = [v for v in vm_configs if v["name"] in args[0]][0] 
            profile = os.path.join(Config.rekall_profile_repository_path(), vm["profile"])
            print("@@@ %s - %s" % (path, profile))
            res = analyser.init_session(path=path, profile=profile)
            data = forge_data(res)
        elif cmd == "change_vm":
            vm = args[0]
            profile = os.path.join(Config.rekall_profile_repository_path(), args[1])
            res = analyser.init_session(vm=vm, profile=profile)
            data = forge_data(res)
        elif cmd == "get_process_list":
            processes = analyser.get_process_list()
            data = forge_data(processes, generate_stix_process_object)
        elif cmd == "get_memory_dump":
            mem_dump = analyser.get_memory_dump(path=Config.memory_dump_path())
            data = forge_data(mem_dump)
        elif cmd == "get_bash_history":
            bash = analyser.get_bash_history()
            data = forge_data(bash, generate_stix_custom_bash_object)
        elif cmd == "get_netstat":
            netstat = analyser.get_network_stat()
            data = forge_data(netstat, generate_stix_netstat_object)
        elif cmd == "get_ifconfig":
            ifconfig = analyser.get_ifconfig()
            data = forge_data(ifconfig, generate_stix_ifconfig_object)
        elif cmd == "get_memmap":
            pid = args[0]
            memmap = analyser.get_memmap(pid)
            data = forge_data(memmap, generate_stix_custom_memmap_object)
        elif cmd == "get_memdump":
            pid = args[0]
            path = args[1]
            mem_dump = analyser.get_process_memdump(pid, path)
            data = forge_data(mem_dump)
        else:
            data = forge_data({"error":"Command is not a valid"})
    elif anly == "sleuthkit":
        if not isinstance(analyser, SleuthKitAnalyser):
            data = forge_data({"error":"Your analyser doesn't match your use"})
        elif cmd == "change_dump":
            path = os.path.join(Config.storage_dump_path(), args[0])
            res = analyser.change_disk(path)
            data = forge_data(res)
        elif cmd == "get_partitions":
            part = analyser.get_partitions()
            data = forge_data(part, generate_stix_custom_partition_object)
        elif cmd == "get_filesytem":
            offset = args[0]
            filesystem = analyser.get_filesystem(offset)
            data = forge_data(filesystem, generate_stix_custom_filesystem_object)
        elif cmd.startswith("get_listdir"):
            path = args[0]
            directory = analyser.list_dir(path)
            data = forge_data((directory, path), generate_stix_directory_object)
        elif cmd.startswith("cat_file"):
            path = args[0]
            outpath = args[1]
            res = analyser.cat_file(path, outpath)
            data = forge_data(res, generate_stix_cat_file_object)
        elif cmd.startswith("mmcat"):
            offset = int(args[0])
            size = int(args[1])
            outpath = args[2]
            mmcat = analyser.mmcat(offset, size, outpath)
            data = forge_data(mmcat)
        else:
            data = forge_data({"error":"Command is not a valid"})
    else:
        if cmd == "sftp_file":
            path = args[0]
            output_path = args[1]
            sftp = sftp_file(path, output_path)
            data = forge_data(sftp)
        else:
            data = forge_data({"error":"Your analyser is not a valid"})

    # data is not set when anly is not supported
    if not data:
        data = forge_data({"error":"No result for your command"})

    # send over kafka if active or send it to log
    if kafka_client:
        kafka_client.send_data(data)
    else:
        logging.info(data)
    return data  # only for testing


def sftp_file(path, output_path=None):
    """ Copies the one file from the monitor to the current machine in the same path
    - path: The path where the file is
    """

    filename = os.path.basename(output_path)
    dirname = os.path.dirname(output_path)

    if (not output_path):
        output_path = "/tmp/%s" % filename

    # you cannot copy same file
    if os.path.exists(output_path):
        output_path = os.path.join(dirname, "new-"+filename)

    # load known hosts
    cnopts = pysftp.CnOpts()
    cnopts.hostkeys.load(os.path.expanduser('~/.ssh/known_hosts'))

    host = Config.monitor_ip()
    username = Config.monitor_ssh_user()
    private_key = Config.monitor_ssh_key()
    status = "failed"

    # try ssh key first, if available
    # else or on fail, try pw
    # only rsa or dsa possible...
    if private_key != "":
        logging.info("Use private key to sftp")
        private_key_pass = Config.monitor_ssh_key_pass()
        try:
            with pysftp.Connection(host=host, username=username, 
                    private_key=private_key, cnopts=cnopts) as srv:
                srv.get(path, output_path) 
                status = "done"
        except:
            pass

    if status != "done":
        logging.info("Use username and password to sftp")
        password = Config.monitor_ssh_pw()
        try:
            with pysftp.Connection(host=host, username=username, password=password,
                    cnopts=cnopts) as srv:
                srv.get(path, output_path) 
                status = "done"
        except:
            pass

    return {"status":status}


