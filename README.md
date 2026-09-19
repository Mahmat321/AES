Implémentation AES en C
Ce projet est une implémentation de l'algorithme AES (FIPS 197) codée de zéro en C à des fins éducatives. Il permet de chiffrer et déchiffrer n'importe quel type de fichier (txt, jpg, pdf, etc.) grâce au mode binaire et au remplissage PKCS#7.

Compilation
Utilisez make pour tout compiler (nécessite GCC) :
 make

Utilisation
Le programme prend trois arguments : l'action (enc ou dec), le fichier d'entrée et le fichier de sortie.

Chiffrer un fichier :
    ./aes enc fichier.txt fichier.aes

Déchiffrer un fichier :
    ./aes dec fichier.aes fichier_restaure.txt


Sécurité:
⚠️ Projet éducatif : Cette implémentation utilise le mode de fonctionnement ECB (Electronic Codebook). Bien que les calculs soient mathématiquement exacts, ce mode n'est pas recommandé pour des données réelles en production car il ne masque pas les motifs répétitifs dans les gros fichiers.