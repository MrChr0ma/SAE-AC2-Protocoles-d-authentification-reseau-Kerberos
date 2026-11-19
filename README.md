# Kerberos simplifié en Python avec AES-GCM

SAÉ PR-CYBER2 (EPITA, Bachelor Cyber 2), projet de recherche encadré par le LRE.
Sujet **AC2 « Protocoles d'authentification réseau : Kerberos »**, groupe 19, référente : Anamaria Costache.

## Le sujet

> Kerberos est un protocole d'authentification basé sur des tickets, qui permet à des parties de prouver mutuellement leur identité de manière sécurisée sur un réseau non sécurisé. Il est conçu selon un modèle client-serveur, avec une hiérarchie claire, et assure une authentification mutuelle.
>
> **Objectif** : implémenter une version simplifiée du protocole Kerberos, en utilisant le chiffrement AES.

Livrables :

- une implémentation (ce dépôt) ;
- une description du protocole et une évaluation de la complexité de l'implémentation ;
- une analyse de l'implémentation : que manque-t-il ? quelles ont été les difficultés ?

Rendu final le **9 décembre 2026** (rapport de 10 pages + slides), soutenance les **10 et 11 décembre 2026**.

Le projet doit faire travailler l'esprit critique : chaque simplification est assumée, justifiée et documentée ([docs/PROTOCOLE.md](docs/PROTOCOLE.md), [docs/ANALYSE.md](docs/ANALYSE.md)).

Cahier des charges du groupe (Google Doc) : <https://docs.google.com/document/d/1lX21QS8WqnF92lALHuot7x585lKqyM144On_t291JEA/edit?usp=sharing>

## Le protocole en bref

```
   Alice (client)                 AS :8800        TGS :8801        Service "mail" :8802
        |                            |                |                    |
   (1)  |--- AS_REQ "alice" -------->|                |                    |
        |<-- E(K_client, K_c_tgs) ---|                |                    |
        |    + TGT = E(K_tgs, ...) --|                |                    |
        |                                             |                    |
   (2)  |--- TGT + E(K_c_tgs, alice+ts) + "mail" ---->|                    |
        |<-- E(K_c_tgs, K_c_service) -----------------|                    |
        |    + ticket = E(K_service, ...) ------------|                    |
        |                                                                  |
   (3)  |--- ticket + E(K_c_service, alice+ts) --------------------------->|
        |<-- E(K_c_service, ts + 1) ---------------------------------------|
        |    (authentification mutuelle)
```

| Clé | Qui la connaît |
| --- | --- |
| K_client | le client (dérivée de son mot de passe) et le KDC |
| K_tgs | le KDC seul (AS et TGS) |
| K_service | le service et le KDC |
| K_c_tgs, K_c_service | générées par le KDC, partagées avec le client (et avec le service pour la seconde) |

Chaque réponse du KDC contient deux parties : une chiffrée avec une clé que le client connaît (preuve d'identité), et un ticket chiffré avec la clé du destinataire, que le client transporte sans pouvoir le lire. Description complète et contrat des messages : [docs/PROTOCOLE.md](docs/PROTOCOLE.md).

Choix techniques : Python 3.10+, bibliothèque `cryptography` avec **AES-GCM** (`AESGCM`, validé par la prof), nonce aléatoire à chaque chiffrement, clé du client dérivée par PBKDF2-HMAC-SHA256, messages JSON sur TCP.

## Répartition

| Partie | Dossier | Responsabilité | Nom | Branche |
| --- | --- | --- | --- | --- |
| 1 | [`client/`](client/README.md) | Dérive K_client du mot de passe, enchaîne les 3 échanges, vérifie `ts + 1`, affiche chaque étape pour la démo | Denis | `feat/client` |
| 2 | [`as_server/`](as_server/README.md) | Reçoit AS_REQ, cherche K_client, génère K_c_tgs, renvoie enc_part + TGT | Sasha | `feat/as-server` |
| 3 | [`tgs_server/`](tgs_server/README.md) | Ouvre le TGT, vérifie l'authenticator, replay cache, génère K_c_service, renvoie le ticket | Hector | `feat/tgs-server` |
| 4 | [`service/`](service/README.md) | Ouvre le ticket, vérifie l'authenticator, replay cache, renvoie `ts + 1`, donne l'accès | Enzo | `feat/service` |
| 5 | [`common/`](common/README.md) | Code commun (déjà écrit) : le relire, le comprendre, maintenir les tests, gérer `init_keys.py`, coordonner l'intégration |  groupe | `feat/common` |

Chaque dossier contient un `README.md` qui explique exactement quoi faire. Commence par lire le tien.

## Organisation du dépôt

```
common/        code commun : chiffrement (crypto.py), réseau (net.py), paramètres (config.py)
client/        partie 1
as_server/     partie 2
tgs_server/    partie 3
service/       partie 4
scripts/       init_keys.py : génère keys.json
tests/         tests pytest
docs/          protocole, ressources, journal de bord, analyse
```

## Installation

Python 3.10 ou plus récent.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python scripts/init_keys.py --password motdepasse
pytest
```

`init_keys.py` crée `keys.json` à la racine : les clés long terme d'Alice, du TGS et du service. Ce fichier contient des secrets, il est dans `.gitignore` et ne doit jamais être committé.

## Lancement

Tout se lance **depuis la racine du dépôt**, en module (`python -m ...`), sinon les imports de `common` échouent. Trois terminaux pour les serveurs, un quatrième pour le client :

```bash
python -m as_server.as_server       # terminal 1, port 8800
python -m tgs_server.tgs_server     # terminal 2, port 8801
python -m service.service           # terminal 3, port 8802
python -m client.client --password motdepasse   # terminal 4
```

Mode clés faibles (8 bits d'entropie, pour la démonstration de force brute) : préfixer **toutes** les commandes, `init_keys.py` compris, par `KRB_KEY_MODE=weak8` (sous PowerShell : `$env:KRB_KEY_MODE="weak8"`). Voir [common/README.md](common/README.md#le-mode-weak8).

## Ordre d'intégration

1. **Client (échange 1) + AS** : le client obtient un TGT et l'affiche.
2. **TGS** : le client obtient un ticket de service.
3. **Service** : authentification mutuelle complète.

Chaque étape est une PR vers `main`. Règles de travail : [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [docs/PROTOCOLE.md](docs/PROTOCOLE.md) : description du protocole, contrat des messages, écarts avec la RFC 4120.
- [docs/ANALYSE.md](docs/ANALYSE.md) : complexité, ce qui manque, difficultés, pistes pour la soutenance.
- [docs/JOURNAL.md](docs/JOURNAL.md) : journal de bord (base du rapport et des slides).
- [docs/RESSOURCES.md](docs/RESSOURCES.md) : sources.
