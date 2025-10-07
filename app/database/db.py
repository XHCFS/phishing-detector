import sqlite3
from . import rawdb
from . import grabrawdata

def init_db():
    rawdb.create_db()
    grabrawdata.main()

