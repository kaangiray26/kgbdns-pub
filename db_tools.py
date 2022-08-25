import re
import time
import secrets
import sqlite3
from hashlib import sha256
from gandi import Gandi

forbidden_domains = [
    "www",
    "test"
]


class DB:
    def __init__(self):
        self.gandi = Gandi()
        self.conn = sqlite3.connect('kgbdns.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.db_setup()

    def check_form_username(self, username):
        return bool(
            re.match(r"^[a-zA-Z0-9\_\-]{3,20}$", username)
        )

    def check_form_email(self, email):
        return bool(
            re.match(r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""", email)
        )

    def check_form_password(self, password):
        return bool(
            re.match(r"^[A-Za-z0-9\<\*\+\!\?\=]{3,32}$", password)
        )

    def check_form_domain(self, domain):
        if domain in forbidden_domains:
            return False

        return bool(
            re.match(r"^[A-Za-z0-9]{1,60}$", domain)
        )

    def check_form_ip(self, ip):
        return bool(
            re.match(
                r"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b", ip)
        )

    def db_setup(self):
        self.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table';")

        if not len(self.cursor.fetchall()):
            self.cursor.execute(
                "CREATE TABLE users (username text PRIMARY KEY, email text NOT NULL, salt text NOT NULL, token text, security_token text)")
            self.cursor.execute(
                "CREATE TABLE hashes (username text PRIMARY KEY, hash text NOT NULL)")
            self.cursor.execute(
                "CREATE TABLE domains (domain text PRIMARY KEY, username text NOT NULL, date int, ip text)")
            self.conn.commit()

    def is_login_valid(self, username, password):
        self.cursor.execute(
            "SELECT salt FROM users WHERE username=?", (username, ))
        salt = self.cursor.fetchone()
        if not salt:
            return False, {"reason": "username invalid."}

        self.cursor.execute(
            "SELECT hash FROM hashes WHERE username=?", (username,))
        hash = self.cursor.fetchone()[0]

        if hash != sha256((password + salt[0]).encode("ascii")).hexdigest():
            return False, {"reason": "username or password invalid."}

        return True, {"username": username}

    def is_register_valid(self, username, email, password):
        if not self.check_form_username(username):
            return False, {"reason": "username invalid."}

        if not self.check_form_email(email):
            return False, {"reason": "email invalid."}

        if not self.check_form_password(password):
            return False, {"reason": "password invalid."}

        self.cursor.execute(
            "SELECT * FROM users WHERE username=? OR email=?", (username, email))

        rows = self.cursor.fetchall()
        if rows:
            return False, {"reason": "username or email exists."}

        token = secrets.token_hex(32)
        security_token = secrets.token_hex(32)
        salt = secrets.token_hex(32)
        hash = sha256((password + salt).encode("ascii")).hexdigest()

        self.cursor.execute("INSERT INTO users VALUES(?, ?, ?, ?, ?)",
                            (username, email, salt, token, security_token))
        self.cursor.execute(
            "INSERT INTO hashes VALUES(?, ?)", (username, hash))
        self.conn.commit()

        return True, {"username": username}

    def get_token(self, username):
        self.cursor.execute(
            "SELECT token FROM users WHERE username=?", (username, ))
        token = self.cursor.fetchone()
        if not token:
            return False, {"reason": "username invalid."}
        return True, {"token": token[0]}

    def get_domains(self, username):
        self.cursor.execute(
            "SELECT domain, ip, date FROM domains WHERE username=?", (username,))
        rows = self.cursor.fetchall()
        if rows:
            return rows
        return []

    def is_domain_valid(self, username, domain):
        self.cursor.execute("SELECT * FROM domains WHERE domain=?", (domain,))
        rows = self.cursor.fetchall()

        if rows:
            return False, {"reason": "domain exists."}

        if not self.check_form_domain(domain):
            return False, {"reason": "domain invalid."}

        if not self.gandi.create_subdomain(domain):
            return False, {"reason": "subdomain creation failed."}

        self.cursor.execute("INSERT INTO domains VALUES(?, ?, ?, ?)",
                            (domain, username, int(time.time()*1000), '1.1.1.1'))
        self.conn.commit()
        return True, {"domain": domain}

    def update_domain(self, domain, token, ip):
        self.cursor.execute(
            "SELECT domain FROM users INNER JOIN domains on users.username = domains.username WHERE token=? ", (token,))
        rows = self.cursor.fetchall()
        if not rows:
            return False

        if not domain in [domain[0] for domain in rows]:
            return False

        if not self.check_form_ip(ip):
            return False

        if not self.gandi.update_subdomain_ip(domain, ip):
            return False

        self.cursor.execute("UPDATE domains SET date=?, ip=? WHERE domain=?", (int(
            time.time()*1000), ip, domain))
        self.conn.commit()
        return True

    def remove_domain(self, domain, token):
        self.cursor.execute(
            "SELECT domain FROM users INNER JOIN domains on users.username = domains.username WHERE token=? ", (token,))
        rows = self.cursor.fetchall()
        if not rows:
            return False

        if not domain in [domain[0] for domain in rows]:
            return False

        if not self.gandi.remove_subdomain(domain):
            return False

        self.cursor.execute("DELETE FROM domains WHERE domain=?", (domain,))
        self.conn.commit()
        return True
