import pytsk3
import magic
import pyqcow
import logging
import json
import os

"""
" Core/sleuthkit_analyser.py
" The SleuthKit Analyser handels the tsk library.
" First, a image must be initialized.
" For this purpose there is the QcowImgInfo class.
" Subsequently, the image can be used to call SleuthKit commands.
" All the commands should be proclaimed by worker.py
"""

class QcowImgInfo(pytsk3.Img_Info):
    """ Handles image info for qemu disks """

    def __init__(self, filename):
        self._qcow_file = pyqcow.file()
        self._qcow_file.open(filename)
        super(QcowImgInfo, self).__init__(
            url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._qcow_file.close()

    def read(self, offset, size):
        self._qcow_file.seek(offset)
        return self._qcow_file.read(size)

    def get_size(self):
        return self._qcow_file.get_media_size()


class SleuthKitAnalyser():

    def __init__(self, path=""):
        self._img_info = None
        self._fs_info = None
        self._volume_info = None
        self._fs_info = None
        self.dump_name = ""
        if path != "":
            self.dump_name = os.path.basename(path)
            self.change_disk(path)

    def reset(self):
        self.__init__()

    def get_dump_name(self):
        return self.dump_name

    def change_disk(self, path):
        """ Read disk image and turn it to volume info
        - path str: The path to the dump
        - return: Success message
        """
        self.dump_name = os.path.basename(path)
        with magic.Magic() as m:
            file_magic = m.id_filename(path)
            if "qemu" in file_magic.lower():
                self._img_info = QcowImgInfo(path) 
            else:
                self._img_info = pytsk3.Img_Info(path) 
        self._volume_info = pytsk3.Volume_Info(self._img_info)
        return {"data": "Successfully changed dump"} 

    def get_partitions(self):
        """ Read partition of the disk.
        Do change_disk first!
        - return: All partitions
        """
        if self._volume_info is None:
            return {"error": "Please choose a storage dump first"}
        data = {}
        for idx, part in enumerate(self._volume_info):
            d = {"addr":part.addr}
            d["desc"] = part.desc.decode("utf-8")
            d["start"] = part.start
            d["offset"] = part.start * 512 
            d["len"] = part.len
            data[idx] = d
        return data

    def get_filesystem(self, offset):
        """ Determine filesystem of disk.
        - return: Filesystem infos
        """
        if self._img_info is None:
            return {"error": "Please choose a storage dump first"} 
        self._fs_info = pytsk3.FS_Info(self._img_info, offset=int(offset))
        data = {"type": str(self._fs_info.info.ftype)} 
        return data

    def list_dir(self, path):
        """ List a directory of the filesystem.
        - path str: Path of the directory
        - return: List of inodes
        """
        if self._fs_info is None:
            return {"error": "Please determine the filesystem first"} 
        directory = self._fs_info.open_dir(path)
        data = {}
        for idx, cur_dir in enumerate(directory):
            name = cur_dir.info.name.name
            inode = cur_dir.info.meta.addr
            node_type = cur_dir.info.name.type
            d = {"name": name.decode("utf-8")}
            d["inode"] = inode
            d["type"] = str(node_type)
            data[str(idx)] = d
        return data

    def cat_file(self, path, outpath):
        """ Copy a file from the dump on the host.
        - path str: Path to file on the storage dump
        - outpath str: Path to the location where to copy the file to
        - return: Both paths
        """
        if self._fs_info is None:
            return {"error": "Please determine the filesystem first"} 
        try:
            f = self._fs_info.open(path)
        except OSError as e:
            return {"error": str(e)}
	
        offset = 0
        size = f.info.meta.size
        BUFF_SIZE = 1024 * 1024

        if os.path.isdir(outpath):
            outpath = os.path.join(outpath, os.path.basename(path))
        out = open(outpath, 'bw')

        while offset < size:
            available_to_read = min(BUFF_SIZE, size - offset)
            data = f.read_random(offset, available_to_read)
            if not data: break
            offset += len(data)
            out.write(data)
        out.close()
        return (path, outpath)

    def mmcat(self, offset, size, outpath):
        """ Copies a part of the storage dump on the host.
        - offset int: The offset from where to start
        - size int: The size of the copy
        - outpath str: Path to the location where to copy to
        - return: Error or success message
        """
        if self._img_info is None:
            return {"error": "Please choose a partition first"} 

        off = 0
        BUFF_SIZE = 1024 * 1024

        if os.path.isdir(outpath):
            outpath = os.path.join(outpath, "mcat_%d" % offset)
        f = open(outpath, 'bw')

        try:
            while(off < size):
                available_to_read = min(BUFF_SIZE, size - off)
                data = self._img_info.read(offset + off, available_to_read)
                if not data: break
                off += len(data)
                f.write(data)
        except Exception as e:
            return {"error": str(e)}
        return {"data": "Your file can be found here: %s" % (outpath)}
