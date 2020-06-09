import sqlite3
import os
from datetime import datetime
from Utils.config_loader import Config

"""
" Flask_Gui/log_database.py
" The Logger stores every working session in a database.
" The researcher can later request previous sessions.
"""

class Logger():
    
    def __init__(self):
        """ Initialize the database if not already exisitng """
        self._timestamp = str(datetime.now().strftime("%s"))
        if not os.path.exists(Config.log_database_path()):
            conn = sqlite3.connect(Config.log_database_path())
            c = conn.cursor()
            c.execute('''CREATE TABLE log
             (id NUMBER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, line TEXT)''')
            conn.commit()
            conn.close()

    def reset(self):
        self.__init__()

    def write(self, line):
        """ Insert a line in the logs with the class timestamp as id """
        conn = sqlite3.connect(Config.log_database_path())
        c = conn.cursor()
        c.execute("INSERT INTO log (id, line) VALUES(?, ?)", (self._timestamp, line))
        conn.commit()
        conn.close()

    def read_all(self, id):
        """ Return all lines from the given timestamp """
        res = []
        conn = sqlite3.connect(Config.log_database_path())
        c = conn.cursor()
        for row in c.execute("SELECT * FROM log WHERE id=?", [id]):
            res.append(row[2])
        return res

    def read_current(self):
        """ Return all lines of the current session """
        return self.read_all(self._timestamp)

    def list_logs(self):
        """ Return all stored session ids """
        res = []
        conn = sqlite3.connect(Config.log_database_path())
        c = conn.cursor()
        for row in c.execute("SELECT id FROM log GROUP BY id"):
            res.append(row[0])
        return res

    def remove(self, id):
        """ Remove the given session """
        conn = sqlite3.connect(Config.log_database_path())
        c = conn.cursor()
        c.execute("DELETE FROM log WHERE id=?", [id])
        conn.commit()
        conn.close()

