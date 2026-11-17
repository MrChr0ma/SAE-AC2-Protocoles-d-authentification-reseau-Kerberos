# Analyse de l'implémentation

Squelette des trois parties demandées par l'énoncé. Les pistes ci-dessous sont à vérifier, compléter et chiffrer au fur et à mesure de l'implémentation, puis à reprendre dans le rapport.

## 1. Évaluation de la complexité

### Complexité du code

À remplir à la fin (commande indicative : `wc -l common/*.py client/*.py as_server/*.py tgs_server/*.py service/*.py`).

| Partie | Lignes de code | Fonctions | Remarques |
| --- | --- | --- | --- |
| `common/` | | | |
| `client/` | | | |
| `as_server/` | | | |
| `tgs_server/` | | | |
| `service/` | | | |

Pistes de comparaison : MIT Kerberos représente plusieurs centaines de milliers de lignes de C ; la majorité concerne ce que nous avons laissé de côté (ASN.1, négociation des algorithmes, royaumes multiples, administration, compatibilité).

### Complexité du protocole

- **Messages** : 3 allers-retours (AS, TGS, service), soit 6 messages pour la première connexion. Pour un deuxième service, le TGT est réutilisé : 2 allers-retours seulement (TGS, service). Le service ne contacte jamais le KDC.
- **Opérations cryptographiques** par authentification complète (à vérifier une fois le code écrit) :
  - client : 1 dérivation PBKDF2, 3 déchiffrements, 2 chiffrements ;
  - AS : 2 chiffrements, 1 génération de clé ;
  - TGS : 2 déchiffrements, 2 chiffrements, 1 génération de clé ;
  - service : 2 déchiffrements, 1 chiffrement.
- **Coût dominant** : la dérivation PBKDF2 (100 000 itérations de HMAC-SHA256, de l'ordre de quelques dizaines de millisecondes), faite une fois côté client ; elle est volontairement lente pour freiner les attaques par dictionnaire. Les opérations AES-GCM sur quelques centaines d'octets sont négligeables (de l'ordre de la microseconde). À mesurer avec `time.perf_counter()`.
- **Mémoire** : le replay cache grossit avec le nombre d'authentifications dans une fenêtre de 5 minutes ; la purge le garde borné. Complexité de la recherche : O(1) (dictionnaire) ; la purge naïve est en O(n) à chaque requête.
- **Taille des messages** : JSON + hexadécimal double la taille des chiffrés ; chaque chiffré ajoute 12 octets de nonce et 16 octets de tag.

### Complexité des attaques (taille de clé)

| Cible | Espace de recherche | Ordre de grandeur |
| --- | --- | --- |
| Clé `weak8` | 2^8 = 256 | instantané (< 1 s en Python) |
| Clé AES-128 aléatoire | 2^128 ≈ 3,4·10^38 | hors de portée (même à 10^12 essais/s, environ 10^19 ans) |
| K_client dérivée d'un mot de passe faible | taille du dictionnaire × coût PBKDF2 | quelques minutes à quelques heures selon le mot de passe |

**Point clé pour le rapport** : avec AES-128, la longueur de la clé n'est plus le maillon faible. C'est **l'entropie du mot de passe** dont K_client est dérivée qui compte : un attaquant qui capture un AS_REP (ou qui le demande lui-même, faute de pré-authentification) peut tester des mots de passe **hors ligne** par dictionnaire, sans jamais interroger le KDC. PBKDF2 et le sel ralentissent l'attaque mais ne l'empêchent pas.

## 2. Ce qui manque pour une vraie implémentation

Liste détaillée des écarts : [PROTOCOLE.md](PROTOCOLE.md#écarts-avec-la-rfc-4120-kerberos-v5). Pistes à développer :

- **Pré-authentification** : sans elle, l'AS distribue à n'importe qui un chiffré attaquable hors ligne (AS-REP roasting).
- **Format standard** : ASN.1/DER, types de chiffrement négociés (`etype`), numéros de version de clé (`kvno`) : nécessaires pour interopérer avec MIT, Heimdal ou Active Directory.
- **KDC unique** avec une vraie base de comptes, séparée des clés des services (*keytab*).
- **Synchronisation des horloges** (NTP) : notre fenêtre de 5 minutes suppose des horloges justes ; sur une seule machine, le problème ne se voit pas.
- **Replay cache persistant** : le nôtre est en mémoire et disparaît au redémarrage du serveur ; un rejeu juste après un redémarrage passerait.
- **Cache de tickets côté client**, renouvellement, délégation, royaumes multiples, PKINIT.
- **Gestion des mots de passe** : politique de complexité, changement de mot de passe (kpasswd), verrouillage après échecs.
- **Robustesse réseau** : limites de débit, protection contre le déni de service (le serveur crée un thread par connexion), journalisation sécurisée.
- **Choix cryptographiques** : la RFC utilise AES-CTS + HMAC ; notre usage de GCM avec nonce aléatoire est sûr tant qu'on chiffre moins de 2^32 messages par clé, ce qui serait à surveiller pour K_tgs sur un gros KDC.

## 3. Difficultés rencontrées

À remplir par chaque personne au fil du projet (voir aussi [JOURNAL.md](JOURNAL.md)).

| Partie | Difficulté | Solution trouvée |
| --- | --- | --- |
| Général | AES-GCM n'accepte pas de clé de 8 bits | Clés AES-128 étirées depuis 8 bits (`weak_key`, mode `weak8`) |
| Général | Risque de réutilisation de nonce signalé par la prof | Nonce aléatoire de 12 octets tiré à chaque `encrypt`, aucun appel direct à `AESGCM` ailleurs |
| | | |

Pistes de difficultés probables : comprendre qui chiffre quoi avec quelle clé ; conversions `bytes`/hex dans le JSON ; synchronisation des horloges et précision des timestamps ; accès concurrent au replay cache ; débogage d'un `DecryptError` (mauvais `aad`, `keys.json` régénéré sans redémarrer les serveurs, mode de clé différent entre deux programmes) ; intégration de parties écrites par des personnes différentes.

## 4. Pistes pour la soutenance

Démonstrations d'attaques possibles **plus tard**, une fois le protocole complet (non implémentées pour l'instant) :

- **Rejeu d'un authenticator** : capturer un AP_REQ valide et le renvoyer tel quel ; il doit être refusé par le replay cache. Montrer aussi qu'il passerait sans replay cache, tant que le timestamp est dans la fenêtre.
- **Ticket expiré** : réutiliser un ticket après `TICKET_LIFETIME` (ou en réduisant temporairement cette valeur) ; il doit être refusé.
- **Ticket volé sans la clé de session** : un attaquant intercepte le ticket mais ne connaît pas K_c_service ; il ne peut pas fabriquer d'authenticator valide, sa requête est refusée.
- **Force brute en mode `weak8`** : intercepter un ticket et retrouver K_service en au plus 256 essais, puis forger un ticket au nom d'un autre utilisateur. Comparer avec le temps théorique en AES-128.
- **Mauvais mot de passe** : le client ne peut pas ouvrir l'AS_REP.
- **Attaque par dictionnaire hors ligne** sur un AS_REP capturé avec un mot de passe faible (illustre le manque de pré-authentification et l'importance de l'entropie du mot de passe).
- **Modification d'un ticket** : changer un octet du TGT ; AES-GCM détecte la modification.
