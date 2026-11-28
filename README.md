# Kerberos simplifié en Python avec AES-GCM

SAÉ PR-CYBER2 2026-2027, EPITA Bachelor Cyber 2, projet de recherche encadré par le LRE (Laboratoire de Recherche de l'EPITA).
Sujet AC2 « Protocoles d'authentification réseau : Kerberos », groupe 19.

Équipe : Hector Decorme, Denis Du, Enzo-Cire Moubongo-Ganga, Sasha Pellereau.
Référente : Anamaria Costache (LRE).

Soutenance : vendredi 4 décembre 2026.

## Le sujet

> Kerberos est un protocole d'authentification basé sur des tickets, qui permet à des parties de prouver mutuellement leur identité de manière sécurisée sur un réseau non sécurisé. Il est conçu selon un modèle client-serveur, avec une hiérarchie claire, et assure une authentification mutuelle.
>
> Objectif : implémenter une version simplifiée du protocole Kerberos, en utilisant le chiffrement AES.

Livrables : l'implémentation (ce dépôt), une description du protocole avec une évaluation de la complexité, et une analyse (ce qui manque, difficultés). Chaque simplification est assumée et expliquée dans [docs/PROTOCOLE.md](docs/PROTOCOLE.md) et [docs/ANALYSE.md](docs/ANALYSE.md).

Cahier des charges du groupe (Google Doc) : <https://docs.google.com/document/d/1lX21QS8WqnF92lALHuot7x585lKqyM144On_t291JEA/edit?usp=sharing>
Rédaction : partie 1 Denis, partie 2 Enzo, partie 3 Hector, partie 4 Enzo et Hector, partie 5 Sasha.

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
| K_c_tgs, K_c_service | clés de session tirées par le KDC, partagées avec le client (et avec le service pour la seconde) |

Chaque réponse du KDC contient une partie chiffrée avec une clé que le client connaît, et un ticket chiffré avec la clé du destinataire, que le client transporte sans pouvoir le lire. Détails et contrat des messages : [docs/PROTOCOLE.md](docs/PROTOCOLE.md).

Choix techniques : Python 3.10+, bibliothèque `cryptography` avec AES-GCM (`AESGCM`, validé par la référente), nonce aléatoire à chaque chiffrement, clé du client dérivée par PBKDF2-HMAC-SHA256, messages JSON sur TCP.

## État au 28 novembre 2026

| Composant | Dossier | Qui | État |
| --- | --- | --- | --- |
| Client | [`client/`](client/README.md) | Denis | fait, fusionné le 20/11 (PR n°3) |
| AS | [`as_server/`](as_server/README.md) | Sasha | fait, fusionné le 25/11 (PR n°5) |
| TGS | [`tgs_server/`](tgs_server/README.md) | Hector | fait : vérifications le 25/11 (PR n°4), terminé le 28/11 (PR n°6) |
| Service | [`service/`](service/README.md) | Enzo | en cours, pas encore fusionné |
| Code commun, tests, squelettes | [`common/`](common/README.md), `tests/`, `scripts/` | Hector | fait le 17/11 |

Sur `main`, le service est encore le squelette : il répond `ERROR "non implémenté"`. Le client va donc jusqu'à l'AP_REQ puis affiche cette erreur. L'authentification complète marchera quand le service sera fusionné.

## Organisation du dépôt

```
common/        code commun : chiffrement (crypto.py), réseau (net.py), paramètres (config.py)
client/        le client (Alice)
as_server/     l'AS
tgs_server/    le TGS
service/       le service "mail"
scripts/       init_keys.py : crée keys.json
tests/         tests pytest
docs/          protocole, analyse, journal, ressources
```

## Installation

Python 3.10 ou plus récent.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python scripts/init_keys.py --password motdepasse
```

`init_keys.py` crée `keys.json` à la racine, avec les clés long terme d'Alice, du TGS et du service. Ce fichier contient des secrets : il est dans `.gitignore` et ne doit jamais être commité.

## Lancement

Quatre programmes : le client et trois serveurs. Tout se lance depuis la racine du dépôt, en module (`python -m ...`), sinon les imports de `common` échouent. Un terminal par programme :

```bash
python -m as_server.as_server                    # terminal 1, AS, port 8800
python -m tgs_server.tgs_server                  # terminal 2, TGS, port 8801
python -m service.service                        # terminal 3, service, port 8802
python -m client.client --password motdepasse    # terminal 4, client
```

Sans `--password`, le client demande le mot de passe au clavier. Si on relance `init_keys.py`, il faut redémarrer les trois serveurs.

### Mode weak8

`KRB_KEY_MODE=weak8` (sous PowerShell : `$env:KRB_KEY_MODE="weak8"`) fait tirer des clés qui n'ont que 256 valeurs possibles. Ce mode ne change que la création des clés :

- pour `init_keys.py` : K_tgs et K_service deviennent faibles ;
- pour l'AS et le TGS : les clés de session K_c_tgs et K_c_service deviennent faibles.

Le client et le service ne créent pas de clé, le mode n'a donc pas d'effet sur eux. K_client reste dérivée du mot de passe. Une clé weak8 reste une clé AES de 16 octets : lancer les programmes avec des modes différents ne provoque pas d'erreur, seules les clés créées en weak8 sont faibles. Voir [common/README.md](common/README.md#le-mode-weak8).

```bash
KRB_KEY_MODE=weak8 python scripts/init_keys.py --password motdepasse
KRB_KEY_MODE=weak8 python -m as_server.as_server
KRB_KEY_MODE=weak8 python -m tgs_server.tgs_server
```

## Tests

```bash
pytest
```

53 tests au 28/11 : `test_crypto.py` (17), `test_net.py` (12), `test_as_server.py` (2), `test_tgs_server.py` (22). Les serveurs sont testés sans réseau, en appelant directement `handle_request`. Il n'y a pas encore de tests pour le client et le service, ni de test de bout en bout.

## Documentation

- [docs/PROTOCOLE.md](docs/PROTOCOLE.md) : le protocole, le contrat des messages, les écarts avec la RFC 4120.
- [docs/ANALYSE.md](docs/ANALYSE.md) : complexité, attaques connues, failles de notre version, ce qui manque, difficultés.
- [docs/JOURNAL.md](docs/JOURNAL.md) : journal de bord.
- [docs/RESSOURCES.md](docs/RESSOURCES.md) : sources.
- [CONTRIBUTING.md](CONTRIBUTING.md) : règles de travail.

## Licence

Licence ISC, voir [LICENSE](LICENSE).
