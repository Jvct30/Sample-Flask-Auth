from flask import Flask, request, jsonify
from models.user import User
from models.database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
# Chave usada para garantir a segurança dos dados da sessão
app.config["SECRET_KEY"] = "your_secret_key"
# Define o caminho do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://admin:admin123@127.0.0.1:3306/flask-crud"

login_manager = LoginManager()
db.init_app(app) # Vincula o banco de dados à instância do app
login_manager.init_app(app) # Configura o controle de login no app

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json # Captura os dados enviados no corpo (JSON) da requisição
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # procura no banco o primeiro usuário com o nome q o user deu
        user = User.query.filter_by(username=username).first() 
        
        # Verifica se o usuário existe e se a senha coincide c a do banco de dados
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticado com sucesso!"})
    return jsonify({"message":"usuario invalido"}), 401

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})
   
# Começo do Crud (C)
@app.route("/User", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message":"Usuário criado com sucesso!"})
    
    return jsonify({"message":"Credenciais inválidas"}), 400
    
@app.route("/User/<int:id_user>", methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"username": user.username}
    
    return jsonify({"message":"Usuário não encontrado"}), 404

@app.route("/User/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message": "operação nao permitida"}), 403
    
    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message":f"Usuário {id_user} atualizado com sucesso"}), 201
    
    return jsonify({"message":"Usuário não encontrado"}), 404
   
@app.route("/User/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if id_user == current_user.id:
        return jsonify({"message":"Deleção proibida"}), 403
    if current_user.role != "admin":
        return jsonify({"message": "operação nao permitida"})
    if user:
        db.session.delete(user)
        db.session.commit()
        return {"message":f"Usuário {id_user} deletado"}

    return jsonify({"message":"Usuário não encontrado"}), 404
    

if __name__ == "__main__":
    app.run(debug=True) # Inicia o servidor em modo de desenvolvimento