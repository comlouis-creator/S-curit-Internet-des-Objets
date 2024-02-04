# PROJET INTERNET DES OBJETS
import requests  # pour faire des requêtes à nist

from flask import *

api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # url de l'api nist
params = {"param1": "valeur1", "param2": "valeur2"}
app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", title="Accueil", content="Hello, World!")


@app.route("/home")
def home():
    response = requests.get(api_url)  # FAIRE UNE REQUETE AVEC L'API NIST
    # params=params
    if response.status_code == 200:
        json_data = response.json()
        print("request successful")
        return render_template("home.html", title="Home", json_data=json_data)
    else:
        return "Request failed, try again"
    return


if __name__ == "__main__":
    app.run(debug=True)
