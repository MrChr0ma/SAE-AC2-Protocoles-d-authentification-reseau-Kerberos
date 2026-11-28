# Le protocole

## Principe

Kerberos permet à un utilisateur de prouver son identité à des services du réseau sans jamais envoyer son mot de passe. Tout repose sur un tiers de confiance, le KDC (*Key Distribution Center*), qui connaît la clé secrète de chaque utilisateur et de chaque service, et qui distribue des tickets à durée de vie limitée. L'idée d'un tiers qui distribue des clés de session vient du protocole de Needham et Schroeder (1978) ; Kerberos y ajoute les timestamps pour se protéger du rejeu.

### Les acteurs

| Acteur | Programme | Port |
| --- | --- | --- |
| Client (Alice) | `client/client.py` | — |
| AS (*Authentication Server*), partie du KDC | `as_server/as_server.py` | 8800 |
| TGS (*Ticket Granting Server*), partie du KDC | `tgs_server/tgs_server.py` | 8801 |
| Service « mail » | `service/service.py` | 8802 |

Les ports et l'adresse (`127.0.0.1`) sont dans `common/config.py`.

### Les clés

| Clé | Type | Qui la connaît | Dans le code |
| --- | --- | --- | --- |
| K_client | long terme, dérivée du mot de passe (PBKDF2, sel = `"alice"`) | le client et le KDC | `derive_key(pwd, "alice")` / `keys["alice"]` |
| K_tgs | long terme, aléatoire | le KDC seul (AS et TGS) | `keys["krbtgt"]` |
| K_service | long terme, aléatoire | le service et le KDC | `keys["mail"]` |
| K_c_tgs | session, tirée par l'AS | le client et le TGS (via le TGT) | dans `AS_REP.enc_part` et le TGT |
| K_c_service | session, tirée par le TGS | le client et le service (via le ticket) | dans `TGS_REP.enc_part` et le ticket |

### Le principe des deux parties

Chaque réponse du KDC contient deux éléments :

1. une partie chiffrée avec une clé que le client connaît : seul le bon client peut l'ouvrir, c'est ce qui prouve son identité ;
2. un ticket chiffré avec la clé du destinataire (TGS ou service) : le client ne peut ni le lire ni le modifier, il le transporte.

Les deux contiennent la même clé de session. Quand le client présente le ticket, il l'accompagne d'un authenticator (son nom et l'heure, chiffrés avec la clé de session) : cela prouve qu'il connaît la clé de session, donc qu'il n'a pas simplement volé le ticket.

## Algorithme

```
1. AS : obtenir le TGT
   Client -> AS : "alice"
   AS tire K_c_tgs
   AS -> Client : E(K_client, K_c_tgs + expiration)               lisible seulement avec le bon mot de passe
                  TGT = E(K_tgs, "alice" + K_c_tgs + expiration)   opaque pour Alice

2. TGS : obtenir un ticket de service
   Client déchiffre avec K_client et récupère K_c_tgs
   Client -> TGS : TGT + E(K_c_tgs, "alice" + timestamp) + "mail"
   TGS ouvre le TGT avec K_tgs, vérifie l'authenticator :
       même client, timestamp dans la fenêtre de 5 min, TGT non expiré, authenticator jamais vu (replay cache)
   TGS tire K_c_service
   TGS -> Client : E(K_c_tgs, K_c_service + expiration)
                   ticket = E(K_service, "alice" + K_c_service + expiration)
                   (expiration du ticket = min(maintenant + 600 s, expiration du TGT))

3. Service
   Client -> Service : ticket + E(K_c_service, "alice" + timestamp)
   Service ouvre le ticket avec K_service, vérifie l'authenticator (mêmes règles), sans contacter le KDC
   Service -> Client : E(K_c_service, timestamp + 1)
   Client vérifie timestamp + 1 (authentification mutuelle)
```

## Contrat des messages

`E(K, aad, {...})` signifie `encrypt(K, {...}, aad)` (voir [common/README.md](../common/README.md)). Les clés de session sont en hexadécimal dans le JSON ; `exp` et `ts` sont des timestamps Unix (`float`). Sur le réseau, chaque message est un objet JSON précédé de sa longueur sur 4 octets big-endian (1 Mo au plus), une requête et une réponse par connexion TCP.

```
AS_REQ   {"type": "AS_REQ",  "client": "alice"}
AS_REP   {"type": "AS_REP",  "enc_part": E(K_client, "AS_REP", {"k_c_tgs", "exp"}),
                             "tgt":      E(K_tgs, "TGT", {"client", "k_c_tgs", "exp"})}

TGS_REQ  {"type": "TGS_REQ", "tgt": ..., "service": "mail",
                             "auth": E(K_c_tgs, "TGS_AUTH", {"client", "ts"})}
TGS_REP  {"type": "TGS_REP", "enc_part": E(K_c_tgs, "TGS_REP", {"k_c_service", "exp"}),
                             "ticket":   E(K_service, "TICKET", {"client", "k_c_service", "exp"})}

AP_REQ   {"type": "AP_REQ",  "ticket": ..., "auth": E(K_c_service, "AP_AUTH", {"client", "ts"})}
AP_REP   {"type": "AP_REP",  "enc_part": E(K_c_service, "AP_REP", {"ts": ts + 1})}

ERROR    {"type": "ERROR",   "reason": "..."}
```

Le `ts` de l'AP_REP est celui de l'authenticator `AP_AUTH` plus 1, pas l'heure du service. Le client garde son `ts` et compare exactement (`client/client.py`).

### Vérifications côté serveur

La colonne « Service » décrit ce qui est prévu : sur `main`, le service n'est pas encore codé.

| Contrôle | AS | TGS | Service |
| --- | --- | --- | --- |
| requête bien formée (type, champs présents) | oui | oui | prévu |
| client connu (dans `keys.json`, pas un nom réservé) | oui | non | non |
| service connu | — | oui | — |
| ticket (TGT ou ticket de service) déchiffrable avec la clé du serveur | — | oui | prévu |
| ticket non expiré (`now < exp`) | — | oui | prévu |
| authenticator déchiffrable avec la clé de session du ticket | — | oui | prévu |
| `ts` est un nombre fini | — | oui | prévu |
| client de l'authenticator = client du ticket | — | oui | prévu |
| `abs(now - ts) <= 300 s` | — | oui | prévu |
| authenticator jamais vu (replay cache, entrée gardée jusqu'à `ts + 600 s`) | — | oui | prévu |

Le TGS ne vérifie pas que le client du TGT existe : il fait confiance à tout TGT qui s'ouvre avec K_tgs. Les messages d'erreur exacts sont dans le README de chaque dossier.

### Propriétés de sécurité visées

- Le mot de passe ne circule jamais : il sert seulement à dériver K_client des deux côtés.
- Un ticket volé est inutile sans la clé de session correspondante, puisqu'il faut produire un authenticator valide.
- Intégrité : AES-GCM authentifie chaque chiffré ; un ticket modifié, même d'un bit, est refusé. L'`aad` empêche de présenter un chiffré à la place d'un autre.
- Anti-rejeu : timestamp dans une fenêtre de 5 minutes, replay cache et durée de vie limitée des tickets. Cela suppose des horloges synchronisées entre client, KDC et service.
- Authentification mutuelle : seul le vrai service peut ouvrir le ticket, donc lui seul connaît K_c_service et peut renvoyer `ts + 1` chiffré.

Les limites de ces propriétés dans notre version sont dans [ANALYSE.md](ANALYSE.md#3-failles-de-notre-implémentation).

## Écarts avec la RFC 4120 (Kerberos v5)

Chaque simplification est volontaire et discutée dans le rapport.

| Notre version | Kerberos v5 (RFC 4120) | Conséquence |
| --- | --- | --- |
| Messages en JSON | Messages encodés en ASN.1 / DER | Plus lisible et facile à déboguer ; pas d'interopérabilité avec un vrai KDC ou client (MIT, Heimdal, Active Directory). |
| AS et TGS séparés, deux programmes qui lisent K_tgs dans `keys.json` | AS et TGS sont deux services d'un même programme, le KDC, avec une base de comptes unique | Plus simple à répartir entre deux personnes ; K_tgs est chargée par deux programmes. |
| Le service renvoie `ts + 1` (repris de Kerberos v4) | En v5, le service renvoie le timestamp (et les microsecondes) de l'authenticator, chiffré | Même rôle ; en v5 l'`+1` est inutile car la forme du message de réponse empêche de le fabriquer sans la clé (ce que fait ici l'`aad`). |
| Pas de pré-authentification : l'AS répond à quiconque donne un nom | Pré-authentification `PA-ENC-TIMESTAMP` : les clients doivent la supporter, chaque royaume décide s'il l'exige | N'importe qui peut obtenir un AS_REP pour « alice » et attaquer son mot de passe hors ligne (AS-REP Roasting). |
| Pas de nonce dans AS_REQ et TGS_REQ | Un nonce dans chaque requête, renvoyé dans la partie chiffrée de la réponse | Le client ne peut pas lier une réponse à sa requête. |
| Un seul royaume | Plusieurs royaumes avec relations d'approbation (*cross-realm*) | Pas de nom de royaume dans les principaux (`alice` au lieu de `alice@EXEMPLE.FR`). |
| Pas de renouvellement ni de délégation de tickets | Tickets renouvelables, transmissibles (*forwardable*), mandataires (*proxiable*) | Il faut refaire tout l'échange quand le ticket expire. |
| Pas de cache de tickets côté client | Cache de tickets (`klist`) | Le client redemande un TGT à chaque lancement. |
| Pas de PKINIT | Authentification initiale possible par certificat (RFC 4556) | Seul le mot de passe est utilisable. |
| Mode `weak8` : clés à 8 bits d'entropie (étirées en 16 octets) | Clés aléatoires de 128 ou 256 bits | Sert à montrer la force brute ; jamais utilisé en vrai. |
| AES-128-GCM | AES-CTS + HMAC (RFC 3962, RFC 8009) | GCM est plus moderne mais impose de ne jamais réutiliser un nonce. |
| Une seule clé par principal, pas de `kvno` ni d'`etype` négocié | `etype` négocié, `kvno` pour changer les clés sans tout casser | Changer une clé oblige à tout redémarrer. |
| Pas d'adresses, de flags, de `starttime`/`renew-till`, de PAC | Nombreux champs dans le ticket | Ticket minimal : client, clé de session, expiration. |
| Replay cache en mémoire seulement | Si le serveur perd son cache, il doit refuser les requêtes pendant la fenêtre de tolérance | Un rejeu juste après un redémarrage passe. |
| Les trois serveurs lisent le même `keys.json` | Chaque service a sa clé dans un *keytab*, le KDC seul a la base | Compromettre le service revient à compromettre le KDC. |
