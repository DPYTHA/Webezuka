from flask import Flask, request, jsonify, redirect, url_for, render_template, session, flash, abort
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime
import os

import json
import traceback
import random
from werkzeug.utils import secure_filename
import jwt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import smtplib
import uuid
from flask import Blueprint, request, jsonify
# Chargement des variables d'environnement
load_dotenv()


app = Flask(__name__, template_folder="templates", static_folder="static")

CORS(app, supports_credentials=True)
colis_bp = Blueprint('colis', __name__)

# Configuration
# Charge les variables depuis .env ou Railway
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # Automatic avec Railway
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Configuration Gmail (SSL)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

EMAIL_SENDER = app.config['MAIL_USERNAME']
EMAIL_ADMIN = "moua19878@gmail.com"

# Initialisation
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
jwt = JWTManager(app)
app.secret_key = "ta_cle_secrete"


with app.app_context():
    db.create_all()


# Configuration Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'  # page de connexion
login_manager.init_app(app)

# Modèles
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    motdepasse = db.Column(db.String(200), nullable=False)
    telephone = db.Column(db.String(30), nullable=False)
    pays = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default="user")
    solde = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default="actif")
    devise = db.Column(db.String(10), default="XOF")
    date_inscription = db.Column(db.DateTime, default=datetime.utcnow)

class Depot(db.Model):
    __tablename__ = 'depots'
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    devise = db.Column(db.String(10), nullable=True)
    montant = db.Column(db.Float, nullable=False)
    pays = db.Column(db.String(100), nullable=False)
    telephone = db.Column(db.String(30), nullable=False)
    mode = db.Column(db.String(50), nullable=False)
    date_envoi = db.Column(db.DateTime, default=datetime.utcnow)
    statut = db.Column(db.String(20), default="en_attente")


# --- MODELE DE BASE DE DONNÉES ---
class Transfert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    expediteur_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Clé étrangère vers utilisateur
    expediteur_nom = db.Column(db.String(100))
    expediteur_email = db.Column(db.String(100))
    
    devise_envoyeur = db.Column(db.String(10))
    montant_envoye = db.Column(db.Float)
    
    pays_destinataire = db.Column(db.String(50))
    devise_destinataire = db.Column(db.String(10))
    montant_recu = db.Column(db.Float)
    
    mode_paiement = db.Column(db.String(50))
    telephone_beneficiaire = db.Column(db.String(50))
    
    date_envoi = db.Column(db.DateTime, default=db.func.current_timestamp())
    valide = db.Column(db.Boolean, default=False)


class Retrait(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    telephone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    montant = db.Column(db.Float, nullable=False)
    frais = db.Column(db.Float, nullable=False)
    montant_debite = db.Column(db.Float, nullable=False)
    montant_recu = db.Column(db.Float, nullable=False)
    mode_paiement = db.Column(db.String(50), nullable=False)
    statut = db.Column(db.String(20), default="en attente")  # en attente, validé, refusé
    date_retrait = db.Column(db.DateTime, default=datetime.utcnow)



# === 1. MODELE COLIS ===
class Colis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_colis = db.Column(db.String(100), unique=True, nullable=False)
    expediteur_nom = db.Column(db.String(100), nullable=False)
    destinataire_nom = db.Column(db.String(100), nullable=False)
    pays_destination = db.Column(db.String(100), nullable=False)
    adresse_destination = db.Column(db.String(255), nullable=False)
    telephone_destinataire = db.Column(db.String(30), nullable=False)
    poids_kg = db.Column(db.Float, nullable=False)
    valeur_estimee = db.Column(db.Float)
    statut = db.Column(db.String(100), default='En attente d\'envoi')
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    date_maj = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)




# Modèle de taux
class Taux(db.Model):
    __tablename__ = 'taux'
    id = db.Column(db.Integer, primary_key=True)
    devise_from = db.Column(db.String(10), nullable=False)
    devise_to = db.Column(db.String(10), nullable=False)
    valeur = db.Column(db.Numeric(10, 4), nullable=False)

  

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def send_email(to, subject, html_content):
    msg = Message(subject=subject, recipients=[to], html=html_content, sender=EMAIL_SENDER)
    try:
        mail.send(msg)
    except Exception as e:
        print("Erreur d’envoi d’email :", e)

# JWT Callbacks
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"msg": "Token invalide"}), 422

@jwt.unauthorized_loader
def unauthorized_callback(err_msg):
    return jsonify({"msg": "Token manquant ou invalide."}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"message": "Token expiré, veuillez vous reconnecter."}), 401

# Décorateurs
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        if not token:
            return jsonify({'message': 'Token manquant'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data.get('user_id') or data.get('id'))
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expiré'}), 401
        except Exception as e:
            return jsonify({'message': 'Token invalide', 'erreur': str(e)}), 401
        if not current_user:
            return jsonify({'message': 'Utilisateur non trouvé'}), 404
        return f(current_user, *args, **kwargs)
    return decorated

#pays associe au devise.
def get_currency_by_country(pays):
    mapping = {
        "Côte d'Ivoire": "XOF",
        "Mali": "XOF",
        "Burkina-Faso": "XOF",
        "Sénégal": "XOF",
        "Cameroun": "XAF",
        "Ghana": "GHS",
        "Mauritanie": "MRU",
        "Niger": "XOF",
        "Congo-Kinshasa": "CDF",
        "Bénin": "XOF",
        "Togo": "XOF",
        "Guinée-Conakry": "GNF",
        "Russie": "RUB"
    }
    return mapping.get(pays, "XOF")  # XOF par défaut si le pays n'est pas reconnu





# Exemple de variable globale temporaire (remplace ça par une BDD dans une vraie app)
taux_conversion = {
    "RUB": { "XOF": 6.8200, "XAF": 0.1413, "GHS": 7.7743, "MRU": 2.0060, "CDF": 0.0276, "GNF": 0.0092 },
    "XOF": { "RUB": 0.1348, "XAF": 1.0040, "GHS": 0.0210, "MRU": 14.248, "CDF": 0.1951, "GNF": 0.0654 },
    "XAF": { "RUB": 7.0764, "XOF": 0.9960, "GHS": 54.961, "MRU": 14.174, "CDF": 0.1943, "GNF": 0.0651 },
    "GHS": { "RUB": 0.1286, "XOF": 0.0181, "XAF": 0.0182, "MRU": 0.2579, "CDF": 0.0035, "GNF": 0.0012 },
    "MRU": { "RUB": 0.4985, "XOF": 0.0702, "XAF": 0.0705, "GHS": 3.8773, "CDF": 0.0136, "GNF": 0.0046 },
    "CDF": { "RUB": 36.255, "XOF": 5.1235, "XAF": 5.1462, "GHS": 282.79, "MRU": 73.404, "GNF": 0.3383 },
    "GNF": { "RUB": 108.29, "XOF": 15.282, "XAF": 15.364, "GHS": 844.66, "MRU": 219.70, "CDF": 2.9568 }
}

@app.route("/")
def splash():
    return render_template("index.html")  # Ton écran de démarrage

@app.route('/home')
def home():
    return render_template('home.html')
@app.route('/register')
def register1():
    return render_template('register.html')
@app.route('/login')
def login1():
    return render_template('register.html')




@app.route('/api/taux', methods=['POST'])
def update_taux():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Données manquantes"}), 400

    global taux_conversion
    taux_conversion = data  # ⚠️ Tu peux remplacer cette ligne par une mise à jour en base de données
    return jsonify({"success": True, "message": "Taux de conversion mis à jour avec succès"})



# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    required_fields = ['nom', 'prenom', 'email', 'motdepasse', 'telephone', 'pays']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f"Le champ '{field}' est requis."}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email déjà utilisé'}), 400
    hashed_pw = generate_password_hash(data['motdepasse'])
    devise = get_currency_by_country(data['pays'])
    user = User(nom=data['nom'], prenom=data['prenom'], email=data['email'],
                motdepasse=hashed_pw, telephone=data['telephone'], pays=data['pays'], devise=devise)
    db.session.add(user)
    db.session.commit()
    send_email(user.email, "Bienvenue sur ÉZUKA", f"<h2>Bonjour {user.prenom}</h2><p>Bienvenue !</p>")
    send_email(EMAIL_ADMIN, "Nouvelle inscription", f"<p>{user.nom} {user.prenom}</p>")
    return jsonify({'message': 'Inscription réussie'}), 201

# Autres routes seront intégrées ici (login, transfert, etc.)

# 🔁 Dictionnaires globaux
pays_to_devise = {
    "côte d’ivoire": "XOF", "sénégal": "XOF", "mali": "XOF", "france": "EUR",
    "états-unis": "USD", "canada": "CAD", "royaume-uni": "GBP", "nigeria": "NGN",
    "maroc": "MAD", "algérie": "DZD", "tunisie": "TND", "afrique du sud": "ZAR",
    "chine": "CNY", "inde": "INR", "russie": "RUB", "japon": "JPY", "turquie": "TRY",
    "cameroun": "XOF", "mauritanie": "MRU", "burkina-faso": "XOF", "benin": "XOF",
    "ghana": "GHS", "niger": "XOF"
}
taux_change = {
    "FCFA": 1, "USD": 600, "EUR": 655, "CAD": 450, "GBP": 750, "NGN": 1.5,
    "MAD": 65, "DZD": 5, "TND": 210, "ZAR": 35, "CNY": 85, "INR": 7,
    "RUB": 9, "JPY": 5, "TRY": 30, "MRU": 16, "GHS": 50
}

# 📦 MODELS (User, Depot, Transfert, Retrait) à ajouter ici selon ton code habituel

# 🔐 Auth
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    if user and check_password_hash(user.motdepasse, data.get('motdepasse')):
        token = create_access_token(identity=user.id)
        return jsonify({
            "token": token,
            "prenom": user.prenom,
            "nom": user.nom,
            "email": user.email,
            "role": user.role,
            "devise": user.devise,     # ← Vérifie que ceci est bien inclus
            "pays": user.pays          # ← Et ceci aussi si utilisé
        }), 200
    return jsonify({"message": "Identifiants incorrects"}), 401

@app.route('/user-info', methods=['GET'])
@jwt_required()
def user_info():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"message": "Utilisateur introuvable"}), 404
    pays_normalise = user.pays.strip().lower() if user.pays else ""
    devise = pays_to_devise.get(pays_normalise, "FCFA")
    return jsonify({
        "user": {
            "prenom": user.prenom,
            "nom": user.nom,
            "email": user.email,
            "solde": user.solde,
            "devise": devise,
            "pays": user.pays
        }
    }), 200



@app.route('/get-solde')
def get_solde():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'solde': user.solde})
    return jsonify({'solde': None}), 404

#depot route

@app.route('/api/depot', methods=['POST'])
def enregistrer_depot():
    data = request.get_json()

    try:
        # Vérification des champs requis
        required_fields = ['nom', 'prenom', 'montant', 'telephone', 'pays', 'mode']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"Le champ '{field}' est requis."}), 400

        # Création du dépôt
        depot = Depot(
            nom=data['nom'],
            prenom=data['prenom'],
            devise=data.get('devise', ''),
            montant=data['montant'],
            telephone=data['telephone'],
            pays=data['pays'],
            mode=data['mode']
        )

        db.session.add(depot)
        db.session.commit()

        # ✉️ Notification ADMIN (HTML avec pub)
        msg_admin = Message(
            subject="💰 Nouvelle intention de dépôt - ÉZUKA",
            sender=app.config['MAIL_USERNAME'],
            recipients=["moua19878@gmail.com"]
        )
        msg_admin.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            .container {{
              font-family: Arial, sans-serif;
              background-color: #f4f4f4;
              padding: 20px;
              color: #333;
            }}
            .card {{
              background-color: white;
              padding: 20px;
              border-radius: 10px;
              box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            }}
            .header {{
              text-align: center;
              color: #0B4D66;
            }}
            .promo {{
              margin-top: 20px;
              text-align: center;
            }}
            .promo img {{
              max-width: 100%;
              border-radius: 10px;
            }}
            .cta {{
              margin-top: 30px;
              text-align: center;
            }}
            .cta a {{
              background: #25D366;
              color: white;
              padding: 12px 24px;
              text-decoration: none;
              border-radius: 25px;
              font-weight: bold;
            }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="card">
              <h2 class="header">💰 Nouvelle intention de dépôt</h2>
              <p><strong>Nom :</strong> {data['prenom']} {data['nom']}</p>
              <p><strong>Montant :</strong> {data['montant']} {data.get('devise', '')}</p>
              <p><strong>Pays :</strong> {data['pays']}</p>
              <p><strong>Téléphone :</strong> {data['telephone']}</p>
              <p><strong>Mode de paiement :</strong> {data['mode']}</p>
              <p><strong>Date :</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>

              <div class="promo">
                <h3>🔥 Promo Spéciale</h3>
                <img src="https://via.placeholder.com/600x200.png?text=Promo+ÉZUKA+Juin" alt="Publicité Ezuka">
                <p><em>Profitez d’un bonus de 10% sur votre premier dépôt ce mois-ci !</em></p>
              </div>

              <div class="cta">
                <a href="https://wa.me/2250757123619">Contacter notre support</a>
              </div>
            </div>
          </div>
        </body>
        </html>
        """

        mail.send(msg_admin)

        # ✉️ Notification UTILISATEUR (texte simple)
        if 'email' in data and data['email']:
            msg_user = Message(
                subject="✅ Confirmation de votre intention de dépôt - ÉZUKA",
                sender=app.config['MAIL_USERNAME'],
                recipients=[data['email']]
            )
            msg_user.body = f"""
Bonjour {data['prenom']},

Nous avons bien reçu votre intention de dépôt de {data['montant']} {data.get('devise', '')}.

Voici le récapitulatif :
- Pays : {data['pays']}
- Téléphone : {data['telephone']}
- Mode de paiement : {data['mode']}
- Date : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

Votre dépôt est en cours de traitement. Vous recevrez une confirmation une fois validé.

Merci pour votre confiance.
L’équipe ÉZUKA
"""
            mail.send(msg_user)

        return jsonify({"message": "✅ Intention enregistrée avec succès."}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# 🚀 Transfert

@app.route('/api/transfert', methods=['POST'])
def transfert():
    data = request.get_json()

    email = data.get('expediteur_email')
    if not email:
        return jsonify({"success": False, "message": "Email expéditeur manquant."}), 400

    utilisateur = User.query.filter_by(email=email).first()
    if not utilisateur:
        return jsonify({"success": False, "message": "Utilisateur non trouvé."}), 404

    try:
        montant_envoye = float(data.get('montant', 0))
        if montant_envoye <= 0:
            return jsonify({"success": False, "message": "Montant invalide."}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Montant incorrect."}), 400

    if utilisateur.solde < montant_envoye:
        return jsonify({"success": False, "message": "Solde insuffisant."}), 400

    devise_source = data.get('devise_expediteur') or utilisateur.devise
    pays_dest = data.get('pays_destinataire')
    if not pays_dest:
        return jsonify({"success": False, "message": "Pays destinataire manquant."}), 400

    devise_dest = data.get('devise_destinataire') or pays_to_devise.get(pays_dest.lower(), "XOF")

    if devise_source == devise_dest:
        taux = 1.0
    else:
        try:
            taux = taux_conversion[devise_source][devise_dest]
        except KeyError:
            return jsonify({"success": False, "message": f"Taux introuvable pour {devise_source} -> {devise_dest}."}), 400

    try:
        montant_recu = float(data.get('montant_recu'))
    except (ValueError, TypeError):
        frais = 0.03
        montant_recu = montant_envoye * taux * (1 - frais)

    utilisateur.solde -= montant_envoye

    transfert = Transfert(
        expediteur_id=utilisateur.id,
        expediteur_nom=data.get('expediteur_nom', utilisateur.prenom + " " + utilisateur.nom),
        expediteur_email=utilisateur.email,
        devise_envoyeur=devise_source,
        montant_envoye=montant_envoye,
        pays_destinataire=pays_dest,
        devise_destinataire=devise_dest,
        montant_recu=montant_recu,
        mode_paiement=data.get('mode_paiement'),
        telephone_beneficiaire=data.get('destinataire')
    )

    db.session.add(transfert)
    db.session.commit()

    try:
        msg = Message(
            subject="Confirmation de votre transfert - ÉZUKA",
            sender=app.config['MAIL_USERNAME'],
            recipients=[utilisateur.email]
        )
        msg.body = f"""
Bonjour {utilisateur.prenom},

Votre transfert a bien été reçu et est en cours de traitement.

Détails du transfert :
- Montant envoyé : {montant_envoye:.2f} {devise_source}
- Montant à recevoir : {montant_recu:.2f} {devise_dest}
- Pays destinataire : {pays_dest}
- Téléphone du bénéficiaire : {data.get('destinataire')}
- Mode de paiement : {data.get('mode_paiement')}

Merci de faire confiance à ÉZUKA.

L'équipe ÉZUKA
"""
        mail.send(msg)

        admin_msg = Message(
            subject="📢 NOUVEAU TRANSFERT ÉZUKA",
            sender=app.config['MAIL_USERNAME'],
            recipients=["moua19878@gmail.com"]
        )
        admin_msg.body = f"""
🎯 NOUVEAU TRANSFERT À TRAITER

Expéditeur : {utilisateur.prenom} {utilisateur.nom} ({utilisateur.email})
Montant envoyé : {montant_envoye:.2f} {devise_source}
Montant à remettre : {montant_recu:.2f} {devise_dest}
Pays destinataire : {pays_dest}
Téléphone du bénéficiaire : {data.get('destinataire')}
Mode de paiement : {data.get('mode_paiement')}
Date : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
"""
        mail.send(admin_msg)

    except Exception as e:
        return jsonify({
            "success": True,
            "message": "Transfert OK mais échec de l'envoi d'email",
            "erreur": str(e)
        }), 200

    return jsonify({
        "success": True,
        "message": f"✅ Transfert réussi ! {montant_envoye:.2f} {devise_source} . Le bénéficiaire recevra {montant_recu:.2f} {devise_dest} dans moins de 5 minutes. Merci pour la confiance!",
        "nouveau_solde": round(utilisateur.solde, 2)
    })




@app.route("/api/transfertsBoard", methods=["GET"])
def get_transfertsBoard():
    transferts = Transfert.query.order_by(Transfert.id.desc()).all()

    result = []
    for t in transferts:
        result.append({
            "id": t.id,
            "nom_expediteur": t.expediteur_nom,
            "devise_envoyeur": t.devise_envoyeur,
            "montant_envoye": t.montant_envoye,
            "pays_destinataire": t.pays_destinataire,
            "devise_destinataire": t.devise_destinataire,
            "montant_recu": t.montant_recu,
            "mode_paiement": t.mode_paiement,
            "telephone_beneficiaire": t.telephone_beneficiaire,
            "date": t.date_envoi.strftime("%Y-%m-%d %H:%M:%S") if t.date_envoi else ""
        })

    return jsonify(result)





@app.route("/retrait", methods=["POST"])
def retrait():
    data = request.get_json()

    email = data.get("email")
    nom = data.get("nom")
    telephone = data.get("telephone")
    montant = float(data.get("montant"))
    frais = float(data.get("frais"))
    montant_debite = montant + frais
    montant_recu = montant
    mode_paiement = data.get("mode_paiement")

    utilisateur = User.query.filter_by(email=email).first()

    if utilisateur and utilisateur.solde >= montant_debite:
        utilisateur.solde -= montant_debite

        retrait = Retrait(
            nom=nom,
            telephone=telephone,
            email=email,
            montant=montant,
            frais=frais,
            montant_debite=montant_debite,
            montant_recu=montant_recu,
            mode_paiement=mode_paiement
        )

        db.session.add(retrait)
        db.session.commit()

        try:
            # 📩 Notification à l'utilisateur
            msg_user = Message(
                subject="💸 Confirmation de votre demande de retrait - ÉZUKA",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg_user.body = f"""
Bonjour {nom},

Votre demande de retrait a bien été enregistrée.

📋 Détails :
- Montant demandé : {montant:.2f}
- Frais : {frais:.2f}
- Montant total débité : {montant_debite:.2f}
- Mode de paiement : {mode_paiement}
- Téléphone : {telephone}

Votre demande est en cours de traitement.
Merci d'avoir utilisé ÉZUKA !

L'équipe ÉZUKA
"""
            mail.send(msg_user)

            # 📩 Notification à l’admin
            msg_admin = Message(
                subject="⚠️ NOUVELLE DEMANDE DE RETRAIT - ÉZUKA",
                sender=app.config['MAIL_USERNAME'],
                recipients=["moua19878@gmail.com"]
            )
            msg_admin.body = f"""
🛑 NOUVEAU RETRAIT À TRAITER

Nom : {nom}
Email : {email}
Téléphone : {telephone}
Montant : {montant:.2f}
Frais : {frais:.2f}
Total débité : {montant_debite:.2f}
Mode de paiement : {mode_paiement}
Date : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
"""
            mail.send(msg_admin)

        except Exception as e:
            return jsonify({
                "status": "warning",
                "message": "Retrait enregistré, mais une erreur s'est produite lors de l'envoi de l'email.",
                "error": str(e)
            }), 200

        return jsonify({"status": "success", "message": "✅ Retrait enregistré et notifications envoyées."}), 200

    else:
        return jsonify({"status": "error", "message": "Solde insuffisant"}), 400


# ADMINISTRATION 
#validation 


@app.route('/valider/<type_op>/<int:op_id>', methods=['POST'])
def valider_operation(type_op, op_id):
    if type_op == 'depot':
        operation = Depot.query.get(op_id)
        if operation:
            operation.statut = "valide"
    elif type_op == 'transfert':
        operation = Transfert.query.get(op_id)
        if operation:
            operation.valide = True
    elif type_op == 'retrait':
        operation = Retrait.query.get(op_id)
        if operation:
            operation.statut = "valide"
    else:
        return jsonify({'message': 'Type d\'opération inconnu'}), 400

    db.session.commit()
    return jsonify({'message': 'Opération validée avec succès'})

@app.route('/annuler/<type_op>/<int:op_id>', methods=['POST'])
def annuler_operation(type_op, op_id):
    if type_op == 'depot':
        op = Depot.query.get(op_id)
        if op: op.statut = "annule"
    elif type_op == 'retrait':
        op = Retrait.query.get(op_id)
        if op: op.statut = "refuse"
    elif type_op == 'transfert':
        op = Transfert.query.get(op_id)
        if op: op.valide = False
    else:
        return jsonify({'message': 'Type invalide'}), 400
    db.session.commit()
    return jsonify({'message': 'Opération annulée avec succès'})

@app.route('/supprimer/<type_op>/<int:op_id>', methods=['DELETE'])
def supprimer_operation(type_op, op_id):
    model = {'depot': Depot, 'retrait': Retrait, 'transfert': Transfert}.get(type_op)
    if model is None:
        return jsonify({'message': 'Type d\'opération invalide'}), 400

    operation = model.query.get(op_id)
    if not operation:
        return jsonify({'message': 'Opération introuvable'}), 404

    db.session.delete(operation)
    db.session.commit()
    return jsonify({'message': 'Opération supprimée avec succès'})


@app.route('/<action>/<type>/<int:id>', methods=['POST'])
def handle_action(action, type, id):
    model_map = {
        'depot': Depot,
        'transfert': Transfert,
        'retrait': Retrait,
        # ajoute 'colis': Colis si tu as un modèle Colis
    }

    if type not in model_map:
        return jsonify({'success': False, 'message': 'Type invalide'}), 400

    model = model_map[type]
    record = model.query.get(id)

    if not record:
        return jsonify({'success': False, 'message': f'{type.capitalize()} introuvable'}), 404

    try:
        if action == 'valider':
            if hasattr(record, 'statut'):
                record.statut = 'validé'
            elif hasattr(record, 'valide'):
                record.valide = True
        elif action == 'annuler':
            if hasattr(record, 'statut'):
                record.statut = 'annulé'
            elif hasattr(record, 'valide'):
                record.valide = False
        elif action == 'supprimer':
            db.session.delete(record)
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Action invalide'}), 400

        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500




# === 2. ROUTE CREATION COLIS ===
@app.route('/colis', methods=['POST'])
def create_colis():
    data = request.json
    nouveau_colis = Colis(
        code_colis = str(uuid.uuid4()),
        expediteur_nom = data['expediteur_nom'],
        destinataire_nom = data['destinataire_nom'],
        pays_destination = data['pays_destination'],
        adresse_destination = data['adresse_destination'],
        telephone_destinataire = data['telephone_destinataire'],
        poids_kg = data['poids_kg'],
        valeur_estimee = data.get('valeur_estimee', 0.0),
    )
    db.session.add(nouveau_colis)
    db.session.commit()
    return jsonify({"success": True, "code_colis": nouveau_colis.code_colis})

# === 3. ROUTE MISE À JOUR DU STATUT ===
@app.route('/api/colis/statut', methods=['POST'])
def update_statut_colis():
    data = request.get_json()
    code_colis = data.get('code_colis')
    nouveau_statut = data.get('nouveau_statut')

    if not code_colis or not nouveau_statut:
        return jsonify({"success": False, "message": "Champs manquants"}), 400

    colis = Colis.query.filter_by(code_colis=code_colis).first()
    if not colis:
        return jsonify({"success": False, "message": "Colis introuvable"}), 404

    colis.statut = nouveau_statut
    colis.date_maj = datetime.now()

    try:
        db.session.commit()
        return jsonify({"success": True, "message": "Statut mis à jour"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500




#SCAN DE COLIS POUR CONNAITRE LES DESTINATIONS 
@colis_bp.route('/colis', methods=['POST'])
def creer_colis():
    data = request.json
    code_colis = str(uuid.uuid4())[:8].upper()

    nouveau_colis = Colis(
        code_colis=code_colis,
        expediteur=data['expediteur'],
        destinataire=data['destinataire'],
        adresse_expediteur=data['adresse_expediteur'],
        adresse_destinataire=data['adresse_destinataire'],
        pays_origine=data['pays_origine'],
        pays_destination=data['pays_destination'],
        poids=data['poids'],
        valeur=data['valeur'],
        statut="En attente de réception à Moscou",
        date_creation=datetime.utcnow()
    )
    db.session.add(nouveau_colis)
    db.session.commit()

    return jsonify({'success': True, 'code_colis': code_colis}), 201


@colis_bp.route('/colis/<code_colis>', methods=['GET'])
def suivre_colis(code_colis):
    colis = Colis.query.filter_by(code_colis=code_colis).first()
    if not colis:
        return jsonify({'success': False, 'message': 'Colis introuvable'}), 404

    return jsonify({
        'success': True,
        'expediteur': colis.expediteur,
        'destinataire': colis.destinataire,
        'adresse_expediteur': colis.adresse_expediteur,
        'adresse_destinataire': colis.adresse_destinataire,
        'pays_origine': colis.pays_origine,
        'pays_destination': colis.pays_destination,
        'poids': colis.poids,
        'valeur': colis.valeur,
        'statut': colis.statut,
        'date_creation': colis.date_creation,
        'date_mise_a_jour': colis.date_mise_a_jour
    })

def generer_code_colis():
    date_str = datetime.utcnow().strftime("%Y%m%d")
    random_digits = str(random.randint(1000, 9999))
    return f"EZK-{date_str}-{random_digits}"




@app.route('/colis/enregistrer', methods=['POST'])
def enregistrer_colis():
    try:
        data = request.get_json()
        code_colis = str(uuid.uuid4())[:8].upper()

        nouveau_colis = Colis(
            code_colis=code_colis,
            expediteur_nom=data['expediteur_nom'],
            destinataire_nom=data['destinataire_nom'],
            pays_destination=data['pays_destination'],
            adresse_destination=data['adresse_destination'],
            telephone_destinataire=data['telephone_destinataire'],
            poids_kg=float(data['poids_kg']),
            valeur_estimee=float(data.get('valeur_estimee', 0))
        )

        db.session.add(nouveau_colis)
        db.session.commit()

        return jsonify({"success": True, "code_colis": code_colis})

    except Exception as e:
        print("Erreur :", traceback.format_exc())
        return jsonify({"success": False, "message": str(e)}), 500

# === ROUTE POUR ADMIN : LISTER TOUS LES COLIS ===


# === ROUTE POUR METTRE À JOUR LE STATUT ===
@app.route('/admin/colis/<int:colis_id>/statut', methods=['POST'])
def modifier_statut(colis_id):
    data = request.json
    nouveau_statut = data.get('statut')
    colis = Colis.query.get(colis_id)
    if not colis:
        return jsonify({"success": False, "message": "Colis introuvable"}), 404
    colis.statut = nouveau_statut
    db.session.commit()
    return jsonify({"success": True, "message": "Statut mis à jour"})


#track colis 
@app.route('/colis/track', methods=['GET'])
def track_colis():
    code = request.args.get('code_colis')
    if not code:
        return jsonify({"success": False, "message": "Code colis manquant."}), 400

    colis = Colis.query.filter_by(code_colis=code).first()
    if not colis:
        return jsonify({"success": False, "message": "Colis non trouvé."}), 404

    return jsonify({
        "success": True,
        "code_colis": colis.code_colis,
        "expediteur_nom": colis.expediteur_nom,
        "destinataire_nom": colis.destinataire_nom,
        "pays_destination": colis.pays_destination,
        "adresse_destination": colis.adresse_destination,
        "telephone_destinataire": colis.telephone_destinataire,
        "poids_kg": colis.poids_kg,
        "valeur_estimee": colis.valeur_estimee,
        "statut": colis.statut,
        "date_creation": colis.date_creation.isoformat(),
        "date_maj": colis.date_maj.isoformat()
    })

   #admin colis 
@app.route("/admin/colis")
def get_colis():
    try:
        colis_list = Colis.query.order_by(Colis.date_creation.desc()).all()
        data = []
        for c in colis_list:
            data.append({
                "code_colis": c.code_colis,
                "expediteur": c.expediteur_nom,
                "destinataire": c.destinataire_nom,
                "telephone_destinataire": c.telephone_destinataire,
                "poids": c.poids_kg,
                "pays": c.pays_destination,
                "date_creation": c.date_creation.strftime("%Y-%m-%d"),
                "statut": c.statut
            })
        return jsonify(success=True, colis=data)
    except Exception as e:
        return jsonify(success=False, message=str(e))
    





    # === Routes API pour dashboard ===
@app.route("/api/users", methods=["GET"])
def get_users():
    users = User.query.order_by(User.date_inscription.desc()).all()
    return jsonify([{ "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,  'telephone': u.telephone,"pays": u.pays,'solde': u.solde } for u in users])

@app.route("/api/depots", methods=["GET"])
def get_depots():
    depots = Depot.query.order_by(Depot.date_envoi.desc()).all()
    return jsonify([{ "id": d.id, "nom": d.nom, "prenom": d.prenom, 'telephone': d.telephone, "montant": d.montant, "pays": d.pays, "mode": d.mode, "date": d.date_envoi.strftime('%Y-%m-%d') } for d in depots])

@app.route("/api/transferts", methods=["GET"])
def get_transferts():
    transferts = Transfert.query.order_by(Transfert.date_envoi.desc()).all()
    return jsonify([{ "id": t.id, "expediteur": t.expediteur_nom, "montant": t.montant_envoye, "pays": t.pays_destinataire, "mode": t.mode_paiement, "date": t.date_envoi.strftime('%Y-%m-%d') } for t in transferts])

@app.route("/api/retraits", methods=["GET"])
def get_retraits():
    retraits = Retrait.query.order_by(Retrait.date_retrait.desc()).all()
    return jsonify([{ "id": r.id, "nom": r.nom, "telephone": r.telephone, "email": r.email, "montant": r.montant, "frais": r.frais, "recu": r.montant_recu, "date": r.date_retrait.strftime('%Y-%m-%d') } for r in retraits])

@app.route("/api/colis", methods=["GET"])
def get_colis_Admin():
    colis = Colis.query.order_by(Colis.date_creation.desc()).all()
    return jsonify([{ "id": c.id, "expediteur": c.expediteur_nom, "destinataire": c.destinataire_nom, "montant": c.valeur_estimee, "pays": c.pays_destination, "date": c.date_creation.strftime('%Y-%m-%d') } for c in colis])



TAX_FILE = os.path.join(os.path.dirname(__file__), 'taux.json')

@app.route('/api/taux', methods=['GET', 'POST'])
def taux_handlerDashboard():
    if request.method == 'GET':
        try:
            with open(TAX_FILE, 'r') as file:
                taux = json.load(file)
            return jsonify(taux)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    elif request.method == 'POST':
        data = request.get_json()
        print("Taux reçus depuis dashboard :", data)  # Ajout important
        try:
            with open(TAX_FILE, 'w') as file:
                json.dump(data, file, indent=4)
            return jsonify({"message": "Taux mis à jour avec succès"})
        except Exception as e:
            print("ERREUR lors de l’écriture :", e)
            return jsonify({"error": str(e)}), 500

    # ✅ Bloc de sécurité final
    return jsonify({"error": "Méthode non autorisée"}), 405


#taux dans postgresql

# Route GET & POST
@app.route('/api/taux', methods=['GET', 'POST'])
def taux_handler():
    if request.method == 'GET':
        taux_dict = {}
        taux_liste = Taux.query.all()
        for taux in taux_liste:
            f, t = taux.devise_from, taux.devise_to
            if f not in taux_dict:
                taux_dict[f] = {}
            taux_dict[f][t] = float(taux.valeur)
        return jsonify(taux_dict)

    elif request.method == 'POST':
        data = request.get_json()
        try:
            for from_devise in data:
                for to_devise in data[from_devise]:
                    valeur = data[from_devise][to_devise]
                    taux = Taux.query.filter_by(devise_from=from_devise, devise_to=to_devise).first()
                    if taux:
                        taux.valeur = valeur
                    else:
                        taux = Taux(devise_from=from_devise, devise_to=to_devise, valeur=valeur)
                        db.session.add(taux)
            db.session.commit()
            return jsonify({"message": "Taux mis à jour avec succès"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

#enregister taux.json dans pgadmin 

TAX_FILE = os.path.join(os.path.dirname(__file__), 'taux.json')

def insert_taux_from_json():
    with app.app_context():
        # Lire le fichier JSON
        with open(TAX_FILE, 'r') as file:
            taux_data = json.load(file)
            print("✔ Contenu JSON :", taux_data) 

        # Optionnel : vider la table avant d'insérer
        Taux.query.delete()

        # Insérer les données
        for from_devise, to_dict in taux_data.items():
            for to_devise, valeur in to_dict.items():
                new_taux = Taux(devise_from=from_devise, devise_to=to_devise, valeur=valeur)
                db.session.add(new_taux)

        db.session.commit()
        print("✅ Taux importés depuis taux.json vers PostgreSQL avec succès.")


#route permettant de changer le taux.json depuis pgadmin 

@app.route('/export-taux', methods=['GET'])
def export_taux_to_json():
    try:
        taux_dict = {}
        all_taux = Taux.query.all()
        for taux in all_taux:
            from_devise = taux.devise_from
            to_devise = taux.devise_to
            valeur = taux.valeur

            if from_devise not in taux_dict:
                taux_dict[from_devise] = {}
            taux_dict[from_devise][to_devise] = valeur

        with open(TAX_FILE, 'w') as file:
            json.dump(taux_dict, file, indent=4)

        return jsonify({"message": "✅ taux.json mis à jour depuis PostgreSQL"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500







# ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crée la table User si inexistante

        # Charger taux.json
        TAX_FILE = os.path.join(os.path.dirname(__file__), 'taux.json')
        with open(TAX_FILE, 'r') as file:
            taux_data = json.load(file)
            print("✔ JSON chargé :", taux_data)

    

        db.session.query(Taux).delete()  # Facultatif : vider la table
        for from_devise, to_dict in taux_data.items():
            for to_devise, valeur in to_dict.items():
                taux = Taux(devise_from=from_devise, devise_to=to_devise, valeur=valeur)
                db.session.add(taux)

        db.session.commit()
        print("✅ Données insérées depuis taux.json")
    
   

    app.run(host="0.0.0.0", port=5000, debug=True)

