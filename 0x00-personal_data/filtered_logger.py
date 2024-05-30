#!/usr/bin/env python3
"""
Filtered logger module
"""

import re
import os
import logging
from typing import List
import mysql.connector
from mysql.connector import connection

PII_FIELDS = ("name", "email", "phone", "ssn", "password")

def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Returns the log message obfuscated.

    Arguments:
    fields -- a list of strings representing all fields to obfuscate
    redaction -- a string representing by what the field will be obfuscated
    message -- a string representing the log line
    separator -- a string representing by which character is separating all fields in the log line (message)
    """
    pattern = '|'.join([f'{field}=[^{separator}]*' for field in fields])
    return re.sub(pattern, lambda m: f"{m.group(0).split('=')[0]}={redaction}", message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record and obfuscate sensitive information.
        """
        original_message = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields, self.REDACTION, original_message, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Creates and returns a logger with a RedactingFormatter.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_db() -> connection.MySQLConnection:
    """
    Connects to the MySQL database using environment variables and returns a connection object.
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    database = os.getenv('PERSONAL_DATA_DB_NAME')
    
    return mysql.connector.connect(
        user=user,
        password=password,
        host=host,
        database=database
    )


def main() -> None:
    """
    Main function to fetch and log user data from the database.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    rows = cursor.fetchall()
    logger = get_logger()
    
    for row in rows:
        message = f"name={row[0]}; email={row[1]}; phone={row[2]}; ssn={row[3]}; password={row[4]}; ip={row[5]}; last_login={row[6]}; user_agent={row[7]};"
        logger.info(message)
    
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
