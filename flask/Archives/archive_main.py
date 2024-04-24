# PROJET INTERNET DES OBJETS
import os
import requests  # pour faire des requêtes à nist
import json
import re
import feedparser
from flask import *
from flask_babel import Babel

#api_url2 = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH"  # url de l'api nist prenant une sévérité basse
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?"
mitre_api_url = "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2018.xml"
#params = {"param1": "valeur1", "param2": "valeur2"}

app = Flask(__name__)

# Fonction pour récupérer les données depuis l'API CVE de MITRE
def get_mitre_data():
    response = requests.get(mitre_api_url)
    if response.status_code == 200:
        # Traitez les données XML ou JSON renvoyées par l'API selon le format
        mitre_data = response.json()  # Par exemple, supposons que l'API renvoie des données JSON
        return mitre_data
    else:
        return None
    
def integrate_cwe_data():
    # URL de l'API CWE de MITRE
    api_url = "https://cwe.mitre.org/data/xml/cwec_v4.3.xml"
    
    try:
        # Faire une requête à l'API CWE
        response = requests.get(api_url)
        
        # Vérifier si la requête a réussi
        if response.status_code == 200:
            # Récupérer les données XML
            cwe_data = response.text
            return cwe_data
        else:
            # En cas d'échec de la requête, afficher un message d'erreur
            return "Failed to fetch CWE data"
    except Exception as e:
        # En cas d'erreur, afficher l'exception
        return str(e)
    
def get_zero_day_initiative_data():
    url = "https://www.zerodayinitiative.com/rss/published/2024/"
    feed = feedparser.parse(url)
    
    if feed.entries:
        # Si le flux RSS contient des entrées, vous pouvez les manipuler ici
        # Par exemple, vous pouvez itérer sur les entrées et afficher leurs titres
        for entry in feed.entries:
            print("Titre:", entry.title)
            print("Lien:", entry.link)
            print("Description:", entry.description)
            print("----------------------------------------")
        
        # Vous pouvez également retourner les données si nécessaire
        return feed.entries
    else:
        # Si le flux RSS est vide ou s'il y a une erreur lors de l'analyse, affichez un message approprié
        print("Aucune donnée trouvée dans le flux RSS")
        return None

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

def integrate_mitre_data():
    mitre_data = []
    try:
        # Utilisez les fonctions de requête appropriées pour obtenir les données de MITRE
        # Exemple avec une requête GET à une API fictive de MITRE
        mitre_api_url = "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2018.xml"
        response = requests.get(mitre_api_url)
        if response.status_code == 200:
            mitre_data = response.json()
        else:
            print("Failed to fetch MITRE data")
    except Exception as e:
        print("Error fetching MITRE data:", e)
    return mitre_data

@app.route("/")
def index():
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

            # rss_url = "https://www.zerodayinitiative.com/rss/published/2024/"
            # rss_data = feedparser.parse(rss_url)
            
            # # Ajout des données du flux RSS à celles déjà existantes
            # for entry in rss_data.entries:
            #     cve = {
            #         'cve': {
            #             'id': entry.title,
            #             # Vous pouvez ajouter d'autres informations du flux RSS ici
            #         }
            #     }
            #     data.append(cve)

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
            mitre_data = integrate_mitre_data()
            data.extend(mitre_data)
            return render_template("home.html", title="Home", data=data)
        else:
            return "Request failed, try again"
    return

if __name__ == "__main__":
    app.run(debug=True)
