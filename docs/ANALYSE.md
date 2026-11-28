# Analyse de l'implémentation

État du code au 28/11/2026 (`main`, après la PR n°6). Les numéros entre crochets renvoient à [RESSOURCES.md](RESSOURCES.md).

## 1. Complexité

### Taille du code

Lignes non vides (docstrings comprises), puis lignes de code seules (sans docstrings ni commentaires).

| Partie | Lignes non vides | Code seul | Fonctions |
| --- | --- | --- | --- |
| `common/` (crypto, net, config) | 216 | 188 | 15 |
| `scripts/init_keys.py` | 43 | 41 | 2 |
| `client/` | 167 | 160 | 7 |
| `as_server/` | 28 | 26 | 2 |
| `tgs_server/` | 93 | 85 | 5 |
| `service/` (squelette) | 60 | 16 | 2 |
| Total | 607 | 516 | 33 |

Les tests font 279 lignes non vides pour 53 tests. Le client et le service n'ont pas de tests.

### Messages

- 3 allers-retours, donc 6 messages par authentification : AS_REQ/AS_REP, TGS_REQ/TGS_REP, AP_REQ/AP_REP.
- 3 connexions TCP : `send_request` ouvre une connexion par requête.
- Le client ne garde pas son TGT entre deux lancements et il n'y a qu'un service : chaque lancement refait les trois échanges.
- Le service ne contacte jamais le KDC.

Taille des messages (JSON compact, comme envoyé par `send_msg`) :

| Message | Octets |
| --- | --- |
| AS_REQ | 34 |
| AS_REP | 470 |
| TGS_REQ | 426 |
| TGS_REP | 490 |
| AP_REQ | 419 |
| AP_REP | 137 |
| Total | 1 976 (2 000 avec les en-têtes de 4 octets) |

Chaque chiffré ajoute 12 octets de nonce et 16 de tag, puis l'hexadécimal double la taille. Un ticket de 91 octets de JSON devient 119 octets chiffrés, soit 238 caractères hex.

### Opérations cryptographiques

| Acteur | `derive_key` | `encrypt` | `decrypt` | `new_session_key` |
| --- | --- | --- | --- | --- |
| Client | 1 | 2 | 3 | 0 |
| AS | 0 | 2 | 0 | 1 |
| TGS | 0 | 2 | 2 | 1 |
| Service (prévu) | 0 | 1 | 2 | 0 |
| Total | 1 | 7 | 7 | 2 |

`init_keys.py` fait en plus, une seule fois, 1 `derive_key` et 2 `new_session_key`.

### Temps mesurés

Machine : Python 3.13.18, `cryptography` 50.0.2, OpenSSL 3.5.9, 4 cœurs Intel Xeon à 2,10 GHz, Linux 6.18, dans un conteneur partagé (les valeurs varient d'un essai à l'autre). Mesures avec `time.perf_counter()`, sans réseau, en appelant directement les fonctions `handle_request`.

| Opération | Moyenne |
| --- | --- |
| `derive_key` (PBKDF2-HMAC-SHA256, 100 000 itérations) | 16 ms |
| `encrypt` d'un ticket (JSON + AES-GCM + hex) | 7,0 µs |
| `decrypt` d'un ticket | 5,3 µs |
| `new_session_key` (aes128 / weak8) | 0,9 µs / 2,7 µs |
| `handle_request` de l'AS | 19,6 µs |
| `handle_request` du TGS, cache vide | 35,1 µs |
| authentification complète, sans réseau | 15,4 ms |

L'authentification complète a été mesurée avec le service de la branche d'Enzo, corrigé localement pour la mesure.

Le coût dominant est PBKDF2 : environ 97 % du temps d'une authentification. Tout le reste (7 chiffrements, 7 déchiffrements, 2 clés, les contrôles) prend moins de 0,5 ms. PBKDF2 est lent exprès, pour freiner les attaques par dictionnaire sur le mot de passe.

### Replay cache

`replay_cache` est un `dict` : recherche et ajout en O(1). Mais `deja_vu` parcourt tout le cache à chaque requête pour purger les vieilles entrées (`list(replay_cache.items())`), donc en O(n) en temps et en mémoire, et sous verrou : les threads passent un par un. n est le nombre d'authenticators acceptés pendant 600 s.

| Entrées dans le cache | 0 | 100 | 1 000 | 10 000 | 100 000 |
| --- | --- | --- | --- | --- | --- |
| Temps de `deja_vu` | 3,0 µs | 7,4 µs | 38 µs | 789 µs | 8,3 ms |

Avec un cache qui grandit de 0 à 5 000 entrées, une requête au TGS passe de 41 µs à 642 µs.

### Coût des attaques sur les clés

| Cible | Espace de recherche | Ordre de grandeur |
| --- | --- | --- |
| Clé `weak8` | 2^8 = 256 | moins d'une seconde |
| Clé AES-128 aléatoire | 2^128 ≈ 3,4·10^38 | hors de portée |
| K_client dérivée d'un mot de passe faible | taille du dictionnaire × 16 ms | 10^6 mots ≈ 4 h 30 sur un cœur, en Python |

Avec AES-128, la longueur de la clé n'est plus le point faible : c'est l'entropie du mot de passe dont K_client est dérivée.

## 2. Attaques connues contre Kerberos

Ces attaques visent le vrai Kerberos, surtout dans Active Directory. Elles sont décrites par MITRE ATT&CK.

- Golden Ticket [8] : avec le hash du compte KRBTGT, l'attaquant forge lui-même des TGT pour n'importe quel compte du domaine. Il faut d'abord un accès privilégié à un contrôleur de domaine pour voler ce hash.
- Silver Ticket [9] : avec le hash d'un compte de service, l'attaquant forge des tickets pour ce seul service. Le KDC n'intervient pas, ce qui rend l'attaque plus discrète.
- Pass-the-Ticket [12] : l'attaquant vole des tickets valides (TGT ou tickets de service), par exemple dans la mémoire d'une machine. Il les réutilise pour s'authentifier ailleurs sans connaître le mot de passe.
- Kerberoasting [10] : un utilisateur du domaine demande des tickets pour des comptes de service ; une partie du ticket est chiffrée avec la clé du compte de service. L'attaquant essaie ensuite de casser ce chiffrement hors ligne pour retrouver le mot de passe du service.
- AS-REP Roasting [11] : pour un compte sans pré-authentification, l'attaquant envoie un AS-REQ sans horodatage chiffré et reçoit quand même un AS-REP. La partie chiffrée avec la clé de l'utilisateur [1] se casse ensuite hors ligne, comme pour le Kerberoasting.

## 3. Failles de notre implémentation

| Faille | Cause dans le code | Conséquence |
| --- | --- | --- |
| Pas de pré-authentification | `as_server/as_server.py` ne vérifie que le nom du client ; l'AS_REQ du client ne contient que `{"type", "client"}` | N'importe qui obtient un AS_REP pour « alice » et attaque son mot de passe hors ligne par dictionnaire (AS-REP Roasting), à 16 ms par essai ici. |
| Un seul `keys.json` pour tous | `scripts/init_keys.py` écrit toutes les clés dans un fichier ; l'AS, le TGS et le service le chargent en entier avec `config.load_keys()` | Compromettre un seul serveur, même le service, donne toutes les clés, K_tgs et K_client comprises. |
| Mode weak8 | `new_session_key` tire `weak_key(secrets.randbelow(256))` ; `init_keys.py` s'en sert pour K_tgs et K_service | K_tgs se retrouve en 256 essais au plus (`test_weak8_force_brute_en_256_essais_max`) à partir de n'importe quel TGT, et l'AS en donne un à qui le demande. Avec K_tgs, on forge un TGT pour n'importe quel nom, que le TGS accepte car `tgs_server.py` ne vérifie pas que le client existe dans `keys.json`. C'est un Golden Ticket en moins d'une seconde. |
| Replay cache en mémoire | `replay_cache` est un `dict` global de `tgs_server.py`, vidé à chaque redémarrage | Un TGS_REQ capturé peut être rejoué juste après un redémarrage, tant que son `ts` est dans la fenêtre de 5 minutes. |
| Pas de chiffrement du transport ni d'authentification du canal | `common/net.py` envoie du JSON en clair sur TCP | Les noms des clients et des services et les types de messages se lisent sur le réseau. Un message `ERROR` n'est pas authentifié : un attaquant peut en injecter un faux, que le client affiche. |
| Un thread par connexion, sans limite | `serve_socket` lance un `threading.Thread` à chaque `accept()`, chaque connexion peut rester ouverte 10 s (`CONN_TIMEOUT`) | Beaucoup de connexions lentes suffisent à épuiser le serveur (déni de service). La purge en O(n) sous verrou aggrave le problème. |
| Horloges synchronisées | toutes les vérifications utilisent `time.time()` de la machine qui vérifie, avec `CLOCK_SKEW = 300` | Si les horloges diffèrent de plus de 5 minutes, l'authentification échoue. Si on peut décaler l'horloge d'un serveur, il accepte des tickets expirés. Sur une seule machine, le problème ne se voit pas. |
| Service pas terminé | `service/service.py` renvoie toujours `error("non implémenté")` sur `main` | Pas d'authentification mutuelle de bout en bout pour l'instant. |

Les tests montrent déjà plusieurs protections qui marchent : rejeu refusé, TGT modifié ou d'une autre clé refusé, timestamp hors fenêtre refusé.

## 4. Ce qui manque pour une vraie implémentation

Liste des écarts : [PROTOCOLE.md](PROTOCOLE.md#écarts-avec-la-rfc-4120-kerberos-v5).

- Pré-authentification `PA-ENC-TIMESTAMP` [1].
- Format standard : ASN.1/DER, types de chiffrement négociés (`etype`), numéros de version de clé (`kvno`), pour parler avec MIT Kerberos, Heimdal ou Active Directory.
- Un KDC unique avec une vraie base de comptes, et un *keytab* par service qui ne contient que sa clé.
- Un nonce dans chaque requête au KDC, pour lier la réponse à la requête.
- Un replay cache qui survit au redémarrage, ou un serveur qui refuse les requêtes pendant la fenêtre de tolérance après un redémarrage, comme le demande la RFC 4120 [1].
- Synchronisation des horloges (NTP).
- Cache de tickets côté client, renouvellement, délégation, plusieurs royaumes, PKINIT.
- Gestion des mots de passe : politique de complexité, changement de mot de passe, verrouillage après plusieurs échecs.
- Robustesse réseau : nombre de connexions limité, journalisation.
- Côté chiffrement, la RFC utilise AES-CTS avec HMAC [3]. Notre GCM avec nonce aléatoire est sûr tant qu'on chiffre beaucoup moins de 2^32 messages par clé, ce qui serait à surveiller pour K_tgs sur un gros KDC.
- Des tests pour le client et le service, un test de bout en bout et une intégration continue.

## 5. Difficultés rencontrées

| Difficulté | Ce qu'on a fait |
| --- | --- |
| AES-GCM refuse une clé de 8 bits, alors que l'idée de départ était une clé de 8 bits | Des clés AES-128 fabriquées à partir d'un seul octet (`weak_key`, mode `weak8`) : 256 clés possibles |
| Ne jamais réutiliser un nonce avec la même clé (consigne de la référente) | Nonce aléatoire de 12 octets tiré à chaque `encrypt`, aucun appel à `AESGCM` ailleurs que dans `common/crypto.py` |
| Planning : deux semaines sans travail (vacances et examens, semaines du 19/10 et du 26/10), soutenance le 4/12 | Le code a été écrit entre le 17/11 et le 28/11 ; le service n'est pas encore fusionné |
| Prise en main de Git et des pull requests | Plusieurs commits faits dans l'interface web de GitHub, branches `feat/...` pas toujours utilisées, une PR qui touchait d'autres dossiers que le sien. Les règles sont dans [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Intégrer le travail de chacun | Un contrat des messages fixé dès le 17/11 (champs, `aad`, clés) et des squelettes à compléter. Chaque serveur se teste seul en appelant `handle_request`. Des écarts sont quand même apparus : la durée de rétention du replay cache n'était pas la même dans le TGS et dans la consigne du service (corrigée dans `service/README.md`) |
