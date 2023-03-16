import os
import mysql.connector
from mysql.connector import Error

# Set up MySQL connection
mydb = mysql.connector.connect(
    host=os.environ.get('MYSQLHOST'),
    user=os.environ.get('MYSQLUSER'),
    password=os.environ.get('MYSQLPASSWORD'),
    database=os.environ.get('MYSQLDATABASE')
)
cursor = mydb.cursor(buffered=True, dictionary=True)

create_user_query = """ 
INSERT INTO users (first_name, last_name, email, password)
VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s)
"""

search_user_with_email_query = """
SELECT *
FROM users
WHERE email=%(email)s
"""