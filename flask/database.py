import sqlite3
import re

class Database:

    def __init__(self) -> None:
        self.connection = sqlite3.connect(database="Database.db")
        self.cursor = self.connection.cursor()
        
    def create_database(self) -> None:
        self.cursor.execute("DROP TABLE IF EXISTS Selects")
        self.cursor.execute("DROP TABLE IF EXISTS CVE")
        self.cursor.execute("""
                            CREATE TABLE IF NOT EXISTS CVE(
                                                            CVE_ID VARCHAR(255) NOT NULL PRIMARY KEY,
                                                            Description VARCHAR(255),
                                                            Risk VARCHAR(255),
                                                            Published DATETIME,
                                                            Modified DATETIME,
                                                            Reference VARCHAR(255)
                            )
                            """)
        self.cursor.execute("""
                            CREATE TABLE IF NOT EXISTS Selects(
                                                            CVE_ID VARCHAR(255) NOT NULL,
                                                            Selector VARCHAR(255),
                                                            FOREIGN KEY(CVE_ID) REFERENCES CVE(CVE_ID)
                            )
                            """)

        
    def add_CVEs(self, cve_data) -> None:
        self.cursor.executemany("INSERT INTO CVE VALUES(?, ?, ?, ?, ?, ?)", cve_data)
        self.connection.commit()

    def add_Selects(self, selects_data) -> None:
        self.cursor.executemany("INSERT INTO Selects VALUES(?, ?)", selects_data)
        self.connection.commit()

    def change_date_format(self, date) -> str:
        date.replace("T", " ")
        return date[0:19]

    def add_data(self, cves) -> dict[list]:

        cve_data = []
        selects_data = []

        checkboxes = {}
        
        for cve in cves:
            
            brands = []
            products = []

            if 'configurations' in cve['cve']:
                for configuration in cve['cve']['configurations']:
                    if 'nodes' in configuration:
                        for node in configuration['nodes']:
                            if 'cpeMatch' in node:
                                for cpe in node['cpeMatch']:
                                    result = re.search("^cpe:.+:h:(\w*):.+$", cpe['criteria'])
                                    if(result is not None):
                                        brand = result.group(1)
                                        if brand not in brands:
                                            brands.append(brand)
                                        if brand not in checkboxes.keys():
                                            checkboxes[brand] = []
                                        result = re.search("^cpe:.+:h:.*:(\w*):.+$", cpe['criteria'])
                                        if(result is not None):
                                            product = result.group(1)
                                            if product not in products:
                                                products.append(product)
                                            if product not in checkboxes[brand]:
                                                checkboxes[brand].append(product)

            cve['cve']['published'] = self.change_date_format(date=str(cve['cve']['published']))
            cve['cve']['lastModified'] = self.change_date_format(date=str(cve['cve']['lastModified']))

            if len(cve['cve']['references']) > 0:

                if 'cvssMetricV31' in cve['cve']['metrics']:
                    cve_data.append((cve['cve']['id'], cve['cve']['descriptions'][0]['value'], cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'], 
                                cve['cve']['published'], cve['cve']['lastModified'], cve['cve']['references'][0]['url']))
                elif 'cvssMetricV2':
                    cve_data.append((cve['cve']['id'], cve['cve']['descriptions'][0]['value'], cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'], 
                                cve['cve']['published'], cve['cve']['lastModified'], cve['cve']['references'][0]['url']))
                else:
                    print(cve)
            else:

                if 'cvssMetricV31' in cve['cve']['metrics']:
                    cve_data.append((cve['cve']['id'], cve['cve']['descriptions'][0]['value'], cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'], 
                                self.change_date_format(cve['cve']['published']), self.change_date_format(cve['cve']['lastModified']), "None"))
                elif 'cvssMetricV2':
                    cve_data.append((cve['cve']['id'], cve['cve']['descriptions'][0]['value'], cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'], 
                                self.change_date_format(cve['cve']['published']), self.change_date_format(cve['cve']['lastModified']), "None"))
                else:
                    print(cve)
            
            for brand in brands:
                selects_data.append((cve['cve']['id'], brand))

            for product in products:
                selects_data.append((cve['cve']['id'], product))
            
        self.add_CVEs(cve_data=cve_data)
        self.add_Selects(selects_data=selects_data)

        return checkboxes

            

    def select_CVEs_select(self, select) -> list:
        cves = self.cursor.execute("SELECT CVE_ID FROM Selects WHERE Selector=?", (select,))
        data = []
        for cve in cves:
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE CVE_ID=?", (cve[0],))
            for n in result:
                data.append({"CVE_ID": n[0], "Description": n[1], "Risk": n[2], "Published": n[3], "Modified": n[4], "Reference": n[5]})
        return data
    
    def select_CVEs_risk(self, risk) -> list:
        result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Risk=?", (risk,))
        data = []
        for n in result:
            data.append({"CVE_ID": n[0], "Description": n[1], "Risk": n[2], "Published": n[3], "Modified": n[4], "Reference": n[5]})
        return data
    
    def select_CVEs_keyword(self, keyword) -> list:
        result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Description LIKE ?", ("%"+keyword+"%",))
        data = []
        for n in result:
            data.append({"CVE_ID": n[0], "Description": n[1], "Risk": n[2], "Published": n[3], "Modified": n[4], "Reference": n[5]})
        return data
    
    def select_CVEs_date(self, before=None, after=None) -> list:
        if before is not None and after is not None:
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Published < ? AND Published > ?", (before, after))
        elif after is None:
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Published < ?", (before,))
        elif before is None:
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Published > ?", (after,))
        else:
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE")
        data = []
        for n in result:
            data.append({"CVE_ID": n[0], "Description": n[1], "Risk": n[2], "Published": n[3], "Modified": n[4], "Reference": n[5]})
        return data
    
    def select_CVEs_date_risk(self, before="", after="", risk="ALL") -> list:
        if before != "" and after != "" and risk != "ALL":
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Published < ? AND Published > ? AND Risk=?", (before, after, risk))
        elif before != "" and after != "":
            return self.select_CVEs_date(before=before, after=after)
        elif after != "" and risk != "ALL":
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Published > ? AND Risk=?", (after, risk))
        elif before != "" and risk != "ALL":
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE WHERE Published < ? AND Risk=?", (before, risk))
        elif before != "":
            return self.select_CVEs_date(before=before)
        elif after != "":
            return self.select_CVEs_date(after=after)
        elif risk != "ALL":
            return self.select_CVEs_risk(risk=risk)
        else:
            return self.select_CVEs()
        result = result.fetchall()
        data = []
        for n in result:
            data.append({"CVE_ID": n[0], "Description": n[1], "Risk": n[2], "Published": n[3], "Modified": n[4], "Reference": n[5]})
        return data

    
    def select_CVEs(self, select=None) -> list:
        if select is not None:
            return self.select_CVEs_select(select=select)
        else :
            result = self.cursor.execute("SELECT CVE_ID, Description, Risk, Published, Modified, Reference FROM CVE")
            result = result.fetchall()
            data = []
            for n in result:
                data.append({"CVE_ID": n[0], "Description": n[1], "Risk": n[2], "Published": n[3], "Modified": n[4], "Reference": n[5]})
            return data
