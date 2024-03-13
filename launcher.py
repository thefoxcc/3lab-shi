import sys
import sqlite3
import hashlib
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox


class Database:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT
            );
        ''')
        self.conn.commit()

    def insert_user(self, username, password_hash):
        try:
            self.cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_password_hash(self, username):
        self.cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        return self.cursor.fetchone()

    def __del__(self):
        self.conn.close()


class RegistrationWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.db = Database('users.db')
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Регистрация')
        self.setGeometry(100, 100, 300, 260)

        layout = QVBoxLayout()

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Имя пользователя')
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText('Пароль')
        layout.addWidget(self.password_input)

        self.password_display = QLineEdit()
        self.password_display.setPlaceholderText('Пароль будет показан здесь')
        self.password_display.setReadOnly(True)  # Сделать поле только для чтения
        layout.addWidget(self.password_display)

        self.hash_display = QLineEdit()
        self.hash_display.setPlaceholderText('Хэш будет показан здесь')
        self.hash_display.setReadOnly(True)  # Сделать поле только для чтения
        layout.addWidget(self.hash_display)

        self.register_button = QPushButton('Регистрация')
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)

        self.login_button = QPushButton('Войти')
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        self.exit_button = QPushButton('Выход')
        self.exit_button.clicked.connect(self.close_application)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if not username or not password:
            QMessageBox.warning(self, 'Ошибка', 'Поля не могут быть пустыми')
            return

        password_hash = hashlib.md5(password.encode()).hexdigest()
        self.password_display.setText(password)  # Показываем пароль
        self.hash_display.setText(password_hash)  # Показываем хэш

        success = self.db.insert_user(username, password_hash)
        
        if success:
            QMessageBox.information(self, 'Успех', 'Регистрация прошла успешно!')
        else:
            QMessageBox.warning(self, 'Ошибка', 'Пользователь с таким именем уже существует')

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if not username or not password:
            QMessageBox.warning(self, 'Ошибка', 'Поля не могут быть пустыми')
            return

        stored_password_hash = self.db.get_password_hash(username)
        
        if stored_password_hash is None:
            QMessageBox.warning(self, 'Ошибка', 'Пользователь не найден')
            return
        
        input_password_hash = hashlib.md5(password.encode()).hexdigest()
        
        if stored_password_hash[0] == input_password_hash:
            QMessageBox.information(self, 'Успех', 'Вход выполнен!')
        else:
            QMessageBox.warning(self, 'Ошибка', 'Неверный пароль')

    def close_application(self):
        self.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = RegistrationWindow()
    window.show()
    sys.exit(app.exec_())