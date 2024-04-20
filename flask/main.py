# PROJET INTERNET DES OBJETS
import os
import requests  # pour faire des requêtes à nist
import json
import re
from flask import *
from flask_babel import Babel

#api_url2 = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH"  # url de l'api nist prenant une sévérité basse
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?"
#params = {"param1": "valeur1", "param2": "valeur2"}

app = Flask(__name__)
babel = Babel(app)

def collect_data(json_data):

    vulnerabilities=[]
    iot = False

    for cve in json_data['vulnerabilities']:

        if 'configurations' in cve['cve']:
            for configuration in cve['cve']['configurations']:
                if 'nodes' in configuration:
                    for node in configuration['nodes']:
                        if 'cpeMatch' in node:
                            for cpe in node['cpeMatch']:
                                if re.search("^cpe:.+:h:.+$", cpe['criteria']) != None:
                                    iot = True

        if iot == True:
            vulnerabilities.append(cve)
            iot = False
            
    return vulnerabilities


def getCheckboxesValues(param):#vient remplir automatiquement le dictionnaire de mots clés
    checkboxes = request.form.getlist('checkboxes')
    print("~~~getting checkboxes values~~~")
    print(checkboxes)
    for value in checkboxes:
        param['keywordSearch']+=f" {value}"

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Récupérer la langue sélectionnée depuis le formulaire
        selected_language = request.form['language']

        # Traduire le contenu en fonction de la langue sélectionnée
        # Ici, vous utiliserez l'API Google Translate ou une autre méthode de traduction
        translated_content = translate_content(selected_language)

        # Renvoyer la page avec le contenu traduit
        return render_template('index.html', content=translated_content)

    # Afficher la page avec le contenu d'origine
    return render_template('index.html')



@app.route("/home",methods=['GET','POST'])
def home():
    if request.method=='GET':
        print("GET METHOD DETECTED")
        response = requests.get(api_url)  # FAIRE UNE REQUETE AVEC L'API NIST
        # params=params
        if response.status_code == 200:
            print("request successful")
            json_data = response.json()
            print(json_data)
            data=collect_data(json_data)
            print(data[0]['cve']['id'])
            return render_template("home.html", title="Home", data=data)
        else:
            return "Request failed, try again"
    
    elif request.method=='POST':
        
        print("POST METHOD DETECTED")
        parameters={}

        if request.form['severity'] != 'ALL':
            parameters['cvssV2Severity'] = request.form['severity']
        parameters['keywordSearch']=request.form['keyWords']

        checkboxes=getCheckboxesValues(parameters)

        #PROBLÈME DANS LE FORMAT DE LA DATE
        if request.form['dateAfter'] !="":
            parameters['pubStartDate']=request.form['dateAfter']+'T00:00:00.000'if request.form['dateAfter'] != "" else ""
        if request.form['dateBefore'] !="" :
            parameters['pubEndDate']=request.form['dateBefore']+'T00:00:00.000' if request.form['dateBefore'] != "" else ""
        
        
        print(parameters)
        response = requests.get(api_url,params=parameters) #FORMULATION DE LA DEMANDE
        print("code de réponse : ", response.status_code)
        if response.status_code // 100==2:
            print("request successful")
            json_data = response.json()
            data=collect_data(json_data)
            #print(data[0]['cve']['id']) 
            return render_template("home.html", title="Home", data=data)
        else:
            return "Request failed, try again"
    return

@app.route('/set-language', methods=['POST'])
def set_language():
    lang_code = request.form['language']
    g.current_language = lang_code
    return redirect(request.referrer)

# Cette fonction peut être utilisée pour injecter les variables nécessaires dans le contexte de tous les modèles.
@app.context_processor
def inject_languages():
    # Remplacez cette liste factice par votre propre liste de langues
    languages = {
        'en': 'English',
        'fr': 'French',
        'es': 'Spanish'
    }
    return dict(LANGUAGES=languages)

def translate_content(language):
    # Code pour traduire le contenu en fonction de la langue sélectionnée
    # Vous utiliserez ici l'API Google Translate ou une autre méthode de traduction
    return translated_content


if __name__ == "__main__":
    app.run(debug=True)