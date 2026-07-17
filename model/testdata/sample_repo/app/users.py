import sqlite3


def get_user_by_id(conn, user_id):
    # 취약: 사용자 입력을 SQL 문자열에 직접 연결 (SQL injection)
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return conn.execute(query).fetchone()


class UserRepository:
    def __init__(self, conn):
        self.conn = conn

    def find_email(self, email):
        return self.conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
