import sqlite3
class SQLighter:
    def __init__(self, database):
        self.connection = sqlite3.connect(database, check_same_thread=False)
        self.cursor = self.connection.cursor()

    #Token_blasck_list
    def jti_exists(self, jti):
        with self.connection:
            return self.cursor.execute('SELECT * FROM `revoked_tokens` WHERE `jti` = ?',(jti,)).fetchone()
    def add_jti(self, jti, now):
        with self.connection:
            return self.cursor.execute('INSERT INTO `revoked_tokens` (`jti`, `created_at`) VALUES(?,?)', (jti, now))

    #users
    def user_exist(self, login):
        with self.connection:
            result = self.cursor.execute('SELECT * FROM `authorization` WHERE `login` = ?', (login,)).fetchall()
            return bool(len(result))
    def email_exist(self, email):
        with self.connection:
            result = self.cursor.execute('SELECT * FROM `authorization` WHERE `email` = ?', (email,)).fetchall()
            return bool(len(result))
    def add_user(self, login, email, password, salt, admin):
        with self.connection:
            return self.cursor.execute('INSERT INTO `authorization` (`login`, `email`, `password`, `salt`, `admin`) VALUES(?,?,?,?,?)', (login, email, password, salt, admin))
    def get_one_user(self, login):
        with self.connection:
            return self.cursor.execute('SELECT `login`, `admin` FROM `authorization` WHERE `login` = ?', (login,)).fetchone()
    def get_password_hash(self, login):
        with self.connection:
            return self.cursor.execute('SELECT `password`, `salt` FROM `authorization` WHERE `login` = ?', (login,)).fetchone()

    #inks
    def url_exists(self, original_url, user):
        with self.connection:
            result = self.cursor.execute('SELECT * FROM `url` WHERE `original_url` = ? AND `user` = ?', (original_url, user)).fetchall()
            return bool(len(result))
    def add_url(self, original_url, short_url, type_url, user):
        with self.connection:
            return self.cursor.execute('INSERT INTO `url` (`original_url`, `short_url`, `type`, `user`) VALUES(?,?,?,?)', (original_url, short_url, type_url, user))
    def update_url(self, type_url, original_url, user):
        with self.connection:
            return self.cursor.execute('UPDATE `url` SET `type` = ?  WHERE `original_url` = ? AND `user` = ?', (type_url, original_url, user))

    def update_url_with_alias(self, type_url, short_url, original_url, user):
        with self.connection:
            return self.cursor.execute('UPDATE `url` SET `type` = ?, `short_url` = ?  WHERE `original_url` = ? AND `user` = ?', (type_url, short_url, original_url, user))
    def get_all_links(self, user):
        with self.connection:
            return self.cursor.execute('SELECT `short_url`, `original_url`, `type`, `count` FROM `url` WHERE `user` = ?', (user,)).fetchall()
    def get_count(self, short_url):
        with self.connection:
            return self.cursor.execute('SELECT `count` FROM `url` WHERE `short_url` = ?', (short_url,)).fetchone()
    def set_count(self, count, short_url):
        with self.connection:
            return self.cursor.execute('UPDATE `url` SET `count` = ? WHERE `short_url` = ?', (count ,short_url)).fetchall()
    def short_url_exists(self, short_url):
        with self.connection:
            result = self.cursor.execute('SELECT * FROM `url` WHERE `short_url` = ?', (short_url,)).fetchall()
            return bool(len(result))
    def get_type(self, short_url):
        with self.connection:
            result = self.cursor.execute('SELECT `type` FROM `url` WHERE `short_url` = ?', (short_url,)).fetchone()
            return result
    def get_user_url(self, short_url):
        with self.connection:
            result = self.cursor.execute('SELECT `user` FROM `url` WHERE `short_url` = ?', (short_url,)).fetchone()
            return result
    def get_short_url(self, original_url, user):
        with self.connection:
            result = self.cursor.execute('SELECT short_url FROM `url` WHERE `original_url` = ? AND `user` = ?', (original_url, user)).fetchone()
            return result
    def get_original_url(self, short_url):
        with self.connection:
            result = self.cursor.execute('SELECT original_url FROM `url` WHERE `short_url` = ?', (short_url,)).fetchone()
            return result
    def delete_link(self, link):
        with self.connection:
            result = self.cursor.execute('DELETE FROM `url` WHERE `short_url` = ?', (link,)).fetchone()
            return result

    def close(self):
        self.connection.close()