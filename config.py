import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "postgresql://ezuka_user:Pytha1991@localhost/ezuka")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'moua19878@gmail.com'  # 🔁 à remplacer
    MAIL_PASSWORD = 'nygojgrubmqseqkq'     # 🔁 à remplacer (mot de passe d'application Gmail)
