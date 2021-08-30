import os.path
import sqlite3

DB_NAME = 'project_db'


class Database:
    def __init__(self):
        if os.path.isfile('project.db'):
            self.conn = sqlite3.connect('project.db', check_same_thread=False)
            self.cursor = self.conn.cursor()
        else:
            self.conn = sqlite3.connect('project.db', check_same_thread=False)
            self.cursor = self.conn.cursor()
            self.create_user_table_sql = '''CREATE TABLE users 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)
                       '''
            self.create_conversation_table_sql = '''CREATE TABLE conversations 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT, receiver TEXT, date TEXT, start_hour TEXT, duration TEXT)
            '''
            self.create_tables(self.create_user_table_sql)
            self.create_tables(self.create_conversation_table_sql)

    def __del__(self):
        self.conn.close()

    def create_tables(self, sql: str):
        self.cursor.execute(sql)
        self.conn.commit()


