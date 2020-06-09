from rekall.plugins.renderers.data_export import DataExportRenderer
from rekall import session
from rekall import plugins
from io import StringIO
from datetime import datetime
import hashlib
import base64
import logging
import json
import os

from Utils.config_loader import Config

"""
" Core/rekall_analyser.py
" The Rekall Analyser handels the Rekall library.
" First, a Rekall session must be initialized.
" Subsequently, the session can be used to call Rekall commands.
" All the commands should be proclaimed by worker.py
"""

class RekallAnalyser():
    
    def __init__(self, path=None, vm=None, profile=None):
        self._session = None
        self.dump_name = ""
        self.init_session(profile=profile, path=path, vm=vm)

    def reset(self):
        self.__init__()

    def init_session(self, profile, path=None, vm=None):
        """ Initialize a rekall session. If path and vm are set, vm is prefered
        - vm str: The name of the target VM listed in xl list
        - path str: The path of the dump file
        - profile str: The profile file
        - return: Success message
        """
        self.dump_name = os.path.basename(path) if path else ""
        if vm:
            self.vm_name = vm
            path = "vmi://xen/" + vm
        if path:
            self._session = session.Session(
                filename=path,
                autodetect=['linux_index'],
                profile=profile,
                logger=logging.getLogger(),
                repository_path=[Config.rekall_profile_repository_path(),
                                 'http://profiles.rekall-forensic.com'])
        return {"data": "Successfully changed dump"} 

    def get_dump_name(self):
        return self.dump_name

    def get_session(self):
        return self._session

    def get_memory_dump(self, path=os.getcwd()):
        """ Dumps the memory of a VM
        - path str: Path where to store dump
        - return: Json with the path to the dump and the sha256
        """
        if not self.vm_name:
            return {"error": "You are not connected to a VM"}

        timestamp = str(datetime.now().strftime("%s"))
        path = os.path.join(path, "%s_%s.aff4" % (self.vm_name, timestamp))

        acquire_cmds = self._session.plugins.aff4acquire(destination=path)
        for i in acquire_cmds:
            logging.info(i[0])

        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                data = f.read(65536)  # 64kb chunks
                if not data:
                    break
                sha256.update(data)

        output = {"path": path, "sha256": sha256.hexdigest()}
        return output


    def get_process_memdump(self, pid, path=os.getcwd()):
        """ Dumps the memory of one process
        - path str: Path where to store dump
        - pid int: Process ID
        - return: Json with the path to the dump and the sha256
        """

        if self._session is None:
            return {"error": "Please create a rekall session first"}

        directory = "%s-%s" % (pid, str(datetime.now().strftime("%s")))
        resultpath = os.path.join(path, directory)

        try:
            os.mkdir(resultpath)
        except FileNotFoundError:
            return {"error": "Path cannot be used"}
        renderer = self._session.GetRenderer()
        memdump = self._session.plugins.memdump(pids=pid, dump_dir=resultpath)
        with renderer.start():
            memdump.render(renderer)

        output = {}
        for filename in os.listdir(resultpath):
            sha256 = hashlib.sha256()
            filepath = os.path.join(resultpath, filename)
            f = open(filepath, 'rb')
            while True:
                data = f.read(65536)  # 64kb chunks
                if not data:
                    break
                sha256.update(data)
            f.close()
            output[filename] = {"path": filepath, "sha256": sha256.hexdigest()}

        return output
    

    def get_process_list(self):
        """ Reads all processes of a VM
        - return: All processes as json
        """
        if self._session is None:
            return {"error": "Please create a rekall session first"}
        string_buff = StringIO()
        processes = self._session.plugins.pslist()
        renderer = DataExportRenderer(session=self._session, output=string_buff)
        with renderer.start():
            processes.render(renderer)
        return json.loads(string_buff.getvalue())


    # rekall issue with refcounter
    def get_network_stat(self):
        """ Reads all sockets used on a VM
        - return: All sockets as json
        """
        if self._session is None:
            return {"error": "Please create a rekall session first"}
        string_buff = StringIO()
        netstat = self._session.plugins.netstat()
        renderer = DataExportRenderer(session=self._session, output=string_buff)
        with renderer.start():
            try:
                netstat.render(renderer)
            except AttributeError as e:
                logging.error(e)
        return json.loads(string_buff.getvalue())


    def get_bash_history(self):
        """ Reads bash history on a VM
        - return: Bash history as json
        """
        if self._session is None:
            return {"error": "Please create a rekall session first"}
        string_buff = StringIO()
        renderer = DataExportRenderer(session=self._session, output=string_buff)
        bash = self._session.plugins.bash()
        with renderer.start():
            bash.render(renderer)
        return json.loads(string_buff.getvalue())


    def get_ifconfig(self):
        """ Reads network interfaces used on a VM
        - return: All interfaces as json
        """
        if self._session is None:
            return {"error": "Please create a rekall session first"}
        string_buff = StringIO()
        renderer = DataExportRenderer(session=self._session, output=string_buff)
        ifconfig = self._session.plugins.ifconfig()
        with renderer.start():
            ifconfig.render(renderer)
        return json.loads(string_buff.getvalue())


    def get_memmap(self, pid):
        """ Reads memmap from one process
        - pid int: Process ID
        - return: memmap
        """
        if self._session is None:
            return {"error": "Please create a rekall session first"}
        string_buff = StringIO()
        renderer = DataExportRenderer(session=self._session, output=string_buff)
        ifconfig = self._session.plugins.memmap(pids=pid)
        with renderer.start():
            ifconfig.render(renderer)
        return json.loads(string_buff.getvalue())
