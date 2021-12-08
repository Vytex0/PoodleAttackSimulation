# PoC de l'attaque POODLE

Ce repository a pour but de visualiser le fonctionnement de l'attaque Poodle. Pour cela, trois classes (Client, Attaquant et Serveur) ont été créées afin de les simuler. On suppose dans notre cas que l'attaquant a déjà réalisé au préalable : 
- une attaque Man In The Middle permettant d'écouter et de modifier les données qui transitent entre le client et le serveur
- un script JS malicieux placé sur la page consulté par le client permettant à l'attaquant de faire envoyer par le client toute les requêtes qu'il souhaite (potentiellement via une faille XSS)


# Utilisation du Poc

Le script est très simple à utiliser, pour la première fois il faut installer la librairie suivante : 

    pip install pycryptodome

Puis pour lancer le script : 

    python poodle.py
