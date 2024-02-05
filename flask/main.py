# PROJET INTERNET DES OBJETS
import requests  # pour faire des requêtes à nist

from flask import *

api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH"  # url de l'api nist prenant une sévérité basse
api_url2 = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00"
params = {"param1": "valeur1", "param2": "valeur2"}
app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", title="Accueil", content="Hello, World!")


@app.route("/home")
def home():
    response = requests.get(api_url2)  # FAIRE UNE REQUETE AVEC L'API NIST
    # params=params
    if response.status_code == 200:
        json_data = response.json()
        print(json_data)
        print("request successful")
        return render_template("home.html", title="Home", json_data=json_data)
    else:
        return "Request failed, try again"
    return


if __name__ == "__main__":
    app.run(debug=True)

#comm test