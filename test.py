import unittest
import tempfile
import shutil
import json
import os
from Core.rekall_analyser import *
from Core.worker import *
from Utils.stix_generator import *
from stix2 import ObservedData


class TestRekallAnalyser(unittest.TestCase):


    def setUp(self):
        self._rekall_analyser = RekallAnalyser(vm="ubuntu1604",
                               profile="/home/fhantke/profile/4.4.0-112-generic")
        self.assertIsNotNone(self._rekall_analyser)

    # Works only local - tmp dir is local
    def test_memory_dump_and_sftp(self):
        tmpdir = "/data/dforensics/tmp/" + str(datetime.now().strftime("%s"))
        os.mkdir(tmpdir)
        dump = self._rekall_analyser.get_memory_dump(path=tmpdir)
        self.assertIsInstance(dump, dict)
        # dump = json.loads(dump)
        self.assertTrue(dump["path"].startswith(tmpdir))
        dumppath = dump["path"]

        data = sftp_file(dumppath, dumppath + "_new")
        dumppath += "_new"
        self.assertTrue(os.path.isfile(dumppath))

        sha256 = hashlib.sha256()
        with open(dumppath, 'rb') as f:
            while True:
                data = f.read(65536)  # 64kb chunks
                if not data:
                    break
                sha256.update(data)

        self.assertEqual(sha256.hexdigest(), dump["sha256"])
        shutil.rmtree(tmpdir)


    def test_process_list(self):
        processes = self._rekall_analyser.get_process_list()
        self.assertIsInstance(processes, list)
        data = generate_stix_process_object(processes)
        self.assertIsInstance(data, ObservedData)

    def test_bash_history(self):
        bash = self._rekall_analyser.get_bash_history()
        self.assertIsInstance(bash, list)
        data = generate_stix_custom_bash_object(bash)
        self.assertIsInstance(data, ObservedData)
    
    def test_netstat(self):
        netstat = self._rekall_analyser.get_network_stat()
        self.assertIsInstance(netstat, list)
        data = generate_stix_netstat_object(netstat)
        self.assertIsInstance(data, ObservedData)

    def test_ifconfig(self):
        ifconfig = self._rekall_analyser.get_ifconfig()
        self.assertIsInstance(ifconfig, list)
        data = generate_stix_ifconfig_object(ifconfig)
        self.assertIsInstance(data, ObservedData)

class TestWorker(unittest.TestCase):


    def setUp(self):
        self._rekall_analyser = RekallAnalyser(vm="ubuntu1604",
                               profile="/home/fhantke/profile/4.4.0-112-generic")
        self.assertIsNotNone(self._rekall_analyser)

    def test_execute_command_rekall(self):
        command = {"analyser":"rekall", "command":["get_bash_history"]}
        data = execute_command(command, self._rekall_analyser)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["type"], "data")
        self.assertEqual(data["command"], command["command"])
        self.assertIsInstance(data["content"], dict)

if __name__ == '__main__':
    unittest.main()
