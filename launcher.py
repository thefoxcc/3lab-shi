import sys
import hashlib
import sqlite3
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel


class Database:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                password_hash TEXT
            );
        ''')
        self.conn.commit()

    def insert_password_hash(self, password_hash):
        self.cursor.execute('INSERT INTO users (password_hash) VALUES (?)', (password_hash,))
        self.conn.commit()

    def find_password_hash(self, password_hash):
        self.cursor.execute('SELECT id FROM users WHERE password_hash = ?', (password_hash,))
        return self.cursor.fetchone()

    def __del__(self):
        self.conn.close()


class AuthorizationWindow(QWidget):
    
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.init_ui()
    
    def check_password(self):
        input_password = self.password_input.text()
        input_password_hash = self.hashing(input_password)
        stored_password_hash = self.db.find_password_hash(input_password_hash)

        if stored_password_hash:
            self.info_label.setText('Пароль верный!')
        else:
            self.info_label.setText('Пароль неверный или не существует в базе данных.')

    def init_ui(self):
        self.setWindowTitle('Шифрование и проверка паролей MD5')
        self.setGeometry(100, 100, 420, 200)

        self.layout = QVBoxLayout()

        self.info_label = QLabel('Введите пароль:')
        self.layout.addWidget(self.info_label)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Пароль')
        self.layout.addWidget(self.password_input)

        self.encrypt_button = QPushButton('Зашифровать и сохранить')
        self.encrypt_button.clicked.connect(self.encrypt_and_save_password)
        self.layout.addWidget(self.encrypt_button)

        self.hash_display = QLineEdit()
        self.hash_display.setReadOnly(True)
        self.hash_display.setPlaceholderText('Хэш MD5')
        self.layout.addWidget(self.hash_display)

        self.check_password_button = QPushButton('Проверить пароль')
        self.check_password_button.clicked.connect(self.check_password)
        self.layout.addWidget(self.check_password_button)

        self.setLayout(self.layout)

    def encrypt_and_save_password(self):
        password = self.password_input.text()
        if password:
            hash_value = self.hashing(password)
            self.hash_display.setText(hash_value)
            self.db.insert_password_hash(hash_value)
            self.info_label.setText('Хэш пароля зашифрован и сохранён в базу.')
        else:
            self.info_label.setText('Введите пароль!')


    def hashing(self, text):
        hash_object = hashlib.md5(text.encode())
        return hash_object.hexdigest()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    db = Database('users.db')
    window = AuthorizationWindow(db)
    window.show()
    sys.exit(app.exec_())