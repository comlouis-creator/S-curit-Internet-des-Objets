# PROJET INTERNET DES OBJETS
import requests  # pour faire des requêtes à nist
import json
import re

#api_url2 = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH"  # url de l'api nist prenant une sévérité basse
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?"
#params = {"param1": "valeur1", "param2": "valeur2"}

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





if __name__ == "__main__":
    app.run(debug=True)