# Projet 1 : Interface de collecte des vulnérabilités des IoT
## Groupe 1 : MEVEL Alexandre, SAFI Bilal, MORLOT--PINTA Louis, MILLOUR Vincent

Installation des prérequis : 
```$ pip install flask requests```
ou 
```$ sudo apt install python-flask python-requests```
ou 
```$ sudo pacman -S python-flask python-requests```

Lancement de l'interface: 
```$ python main.py```

Puis, ouvrir l'url `127.0.0.1:5000` dans un navigateur

À partir de là, configurer les filtres comme souhaité :
- Severity
- Bornes temporelles de publication

Attention à correctement paramétrer les bornes, `dateBefore` est une limite maximale, `dateAfter` est minimale

Dans le panneau coulissant, déroulable grâce à un clic sur l'icône "réglage"
- Cochage des cases à cocher (Marques et Types d'objets), qui définissent les mots clés à rechercher 
- Recherche par mots clés dans l'entrée textuelle

Cliquer sur "Search" pour effectuer la recherche

Si désiré, trier les résultats grâce à l'entrée de texte "Filter results" et cliquer sur la loupe.