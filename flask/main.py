# PROJET INTERNET DES OBJETS
import requests  # pour faire des requêtes à nist
import json
import re
from flask import *

from database import Database

#api_url2 = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH"  # url de l'api nist prenant une sévérité basse
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?"
#params = {"param1": "valeur1", "param2": "valeur2"}

selects = {}

app = Flask(__name__)

def request_api(api):
    database = Database()
    database.create_database()
    parameters={}
    parameters['pubStartDate']='2024-01-01T04:00:00.000'
    parameters['pubEndDate']='2024-03-01T04:00:00.000'
    response = requests.get(api, params=parameters)
    if response.status_code // 100==2:
        print("request successful")
        json_data = response.json()
        data=collect_data(json_data)
        result = database.add_data(cves=data)
        return result
        
    else:
        print("Request failed, try again")

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

def add_data(json_data):

    cves = collect_data(json_data=json_data)

    for cve in cves:

        brands = []
        products = []

        if 'configurations' in cve['cve']:
            for configuration in cve['cve']['configurations']:
                if 'nodes' in configuration:
                    for node in configuration['nodes']:
                        if 'cpeMatch' in node:
                            for cpe in node['cpeMatch']:
                                result = re.search("^cpe:.+:h:(.*):.+$", cpe['criteria'])
                                if(result is not None):
                                    brands.append(result.group())
                                result = re.search("^cpe:.+:h:.*:(.*):.+$", cpe['criteria'])
                                if(result is not None):
                                    products.append(result.group())


def getSelectsObjectsValues():
    selects = request.form.getlist('select_objects')
    print("~~~getting selects values~~~")
    print(selects)
    return selects[0]

def getSelectsBrandsValues():
    selects = request.form.getlist('select_brands')
    print("~~~getting selects values~~~")
    print(selects)
    return selects[0]

@app.route("/")
def index():
    return render_template("index.html", title="Accueil", content="Hello, World!", selects=selects)


@app.route("/home",methods=['GET','POST'])
def home():
    database = Database()
    if request.method=='GET':
        print("GET METHOD DETECTED")
        data = database.select_CVEs()
        return render_template("home.html", title="Home", data=data, selects=selects)
    
    elif request.method=='POST':
        print("POST METHOD DETECTED")
        data = []
        select_products=getSelectsObjectsValues()
        select_brands=getSelectsBrandsValues()

        if request.form['severity'] != 'ALL' or request.form['dateAfter'] !="" or request.form['dateBefore'] !="":
            data = database.select_CVEs_date_risk(before=request.form['dateBefore'], after=request.form['dateAfter'], risk=request.form['severity'])

        elif request.form['keyWords'] != "":
            data = database.select_CVEs_keyword(keyword=request.form['keyWords'])
        
        elif select_products != "" and select_brands != "":

            data = data + database.select_CVEs(select=select_products)
            data = data + database.select_CVEs(select=select_brands)

        elif select_products == "":

            data = data + database.select_CVEs(select=select_brands)

        elif select_brands == "":

            data = data + database.select_CVEs(select=select_products)

        else:

            data = data + database.select_CVEs()
        
        return render_template("home.html", title="Home", data=data, selects=selects)
        
    return


if __name__ == "__main__":
    selects=request_api(api=api_url)
    app.run(debug=True)
