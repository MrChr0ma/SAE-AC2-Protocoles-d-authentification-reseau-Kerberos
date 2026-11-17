# Le protocole

## Principe

Kerberos permet à un utilisateur de prouver son identité à des services du réseau **sans jamais envoyer son mot de passe**. Tout repose sur un tiers de confiance, le **KDC** (*Key Distribution Center*), qui connaît la clé secrète de chaque utilisateur et de chaque service, et qui distribue des tickets à durée de vie limitée. L'idée d'un tiers qui distribue des clés de session vient du protocole de Needham et Schroeder (1978) ; Kerberos y ajoute les timestamps pour se protéger du rejeu.

### Les acteurs

| Acteur | Programme | Port |
| --- | --- | --- |
| Client (Alice) | `client/client.py` | — |
| AS (*Authentication Server*), partie du KDC | `as_server/as_server.py` | 8800 |
| TGS (*Ticket Granting Server*), partie du KDC | `tgs_server/tgs_server.py` | 8801 |
| Service « mail » | `service/service.py` | 8802 |

### Les clés

| Clé | Type | Qui la connaît | Dans le code |
| --- | --- | --- | --- |
| K_client | long terme, dérivée du mot de passe (PBKDF2, sel = `"alice"`) | le client et le KDC | `derive_key(pwd, "alice")` / `keys["alice"]` |
| K_tgs | long terme, aléatoire | le KDC seul (AS et TGS) | `keys["krbtgt"]` |
| K_service | long terme, aléatoire | le service et le KDC | `keys["mail"]` |
| K_c_tgs | session, générée par l'AS | le client et le TGS (via le TGT) | dans `AS_REP.enc_part` et le TGT |
| K_c_service | session, générée par le TGS | le client et le service (via le ticket) | dans `TGS_REP.enc_part` et le ticket |

### Le principe des deux parties

Chaque réponse du KDC contient deux éléments :

1. une partie chiffrée avec une clé que **le client** connaît : seul le bon client peut l'ouvrir, c'est ce qui prouve son identité ;
2. un ticket chiffré avec la clé du **destinataire** (TGS ou service) : le client ne peut ni le lire ni le modifier, il le transporte comme un badge.

Les deux contiennent la même clé de session. Quand le client présente le ticket, il l'accompagne d'un **authenticator** (son nom et l'heure, chiffrés avec la clé de session) : cela prouve qu'il connaît la clé de session, donc qu'il n'a pas simplement volé le ticket.

## Algorithme

```
1. AS : obtenir le TGT
   Client -> AS : "alice"
   AS génère K_c_tgs
   AS -> Client : E(K_client, K_c_tgs + expiration)               lisible seulement avec le bon mot de passe
                  TGT = E(K_tgs, "alice" + K_c_tgs + expiration)   opaque pour Alice

2. TGS : obtenir un ticket de service
   Client déchiffre avec K_client et récupère K_c_tgs
   Client -> TGS : TGT + E(K_c_tgs, "alice" + timestamp) + "mail"
   TGS ouvre le TGT avec K_tgs, vérifie l'authenticator :
       même client, timestamp dans la fenêtre de 5 min, TGT non expiré, authenticator jamais vu (replay cache)
   TGS génère K_c_service
   TGS -> Client : E(K_c_tgs, K_c_service + expiration)
                   ticket = E(K_service, "alice" + K_c_service + expiration)

3. Service
   Client -> Service : ticket + E(K_c_service, "alice" + timestamp)
   Service ouvre le ticket avec K_service, vérifie l'authenticator (mêmes règles), sans contacter le KDC
   Service -> Client : E(K_c_service, timestamp + 1)
   Client vérifie timestamp + 1 (authentification mutuelle)
```

## Contrat des messages

`E(K, aad, {...})` signifie `encrypt(K, {...}, aad)` (voir [common/README.md](../common/README.md)). Les clés de session sont en hexadécimal dans le JSON ; `exp` et `ts` sont des timestamps Unix (`float`). Sur le réseau, chaque message est un objet JSON précédé de sa longueur sur 4 octets big-endian, une requête et une réponse par connexion TCP.

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

### Vérifications côté serveur

| Contrôle | AS | TGS | Service |
| --- | --- | --- | --- |
| client connu | oui | — | — |
| service connu | — | oui | — |
| ticket (TGT ou ticket de service) déchiffrable avec la clé du serveur | — | oui | oui |
| ticket non expiré (`now < exp`) | — | oui | oui |
| authenticator déchiffrable avec la clé de session du ticket | — | oui | oui |
| client de l'authenticator = client du ticket | — | oui | oui |
| `abs(now - ts) <= 300 s` | — | oui | oui |
| authenticator jamais vu (replay cache) | — | oui | oui |

Les messages d'erreur exacts sont listés dans le README de chaque partie.

### Propriétés de sécurité visées

- **Le mot de passe ne circule jamais** : il sert seulement à dériver K_client des deux côtés.
- **Un ticket volé est inutile** sans la clé de session correspondante, puisqu'il faut produire un authenticator valide.
- **Intégrité** : AES-GCM authentifie chaque chiffré ; un ticket modifié, même d'un bit, est refusé. L'`aad` empêche de présenter un chiffré à la place d'un autre.
- **Anti-rejeu** : timestamp dans une fenêtre de 5 minutes + replay cache + durée de vie limitée des tickets. Cela suppose des horloges synchronisées entre client, KDC et service.
- **Authentification mutuelle** : seul le vrai service peut ouvrir le ticket, donc lui seul connaît K_c_service et peut renvoyer `ts + 1` chiffré.

## Écarts avec la RFC 4120 (Kerberos v5)

Chaque simplification est volontaire ; elle est à discuter dans le rapport.

| Notre version | Kerberos v5 réel (RFC 4120) | Conséquence |
| --- | --- | --- |
| Messages en **JSON** | Messages encodés en **ASN.1 / DER** | Plus lisible et facile à déboguer ; pas d'interopérabilité avec un vrai KDC ou client (MIT, Heimdal, Active Directory). |
| **AS et TGS séparés**, deux programmes qui lisent K_tgs dans `keys.json` | AS et TGS sont deux services d'un même programme, le KDC, avec une base de comptes unique | Plus simple à répartir entre deux personnes ; la clé K_tgs est dupliquée. |
| Le service renvoie **`ts + 1`** (repris de **Kerberos v4**) | En v5, le service renvoie le timestamp (et le champ microsecondes) de l'authenticator, chiffré | Même rôle (preuve que le service a ouvert le ticket) ; en v5 l'`+1` est inutile car le message de réponse a un type différent (ce que fait ici l'`aad`). |
| **Pas de pré-authentification** : l'AS répond à quiconque donne un nom | Pré-authentification `PA-ENC-TIMESTAMP` activée par défaut : le client prouve d'abord qu'il connaît K_client | N'importe qui peut obtenir un AS_REP pour « alice » et attaquer son mot de passe hors ligne (*AS-REP roasting*). |
| **Un seul royaume** | Plusieurs royaumes avec relations d'approbation (*cross-realm*) | Pas de nom de royaume dans les principaux (`alice` au lieu de `alice@EXEMPLE.FR`). |
| **Pas de renouvellement ni de délégation** de tickets | Tickets renouvelables, transmissibles (*forwardable*), mandataires (*proxiable*), délégation contrainte | Il faut refaire tout l'échange quand le ticket expire. |
| **Pas de cache de tickets persistant** | Cache de tickets (`/tmp/krb5cc_*`, `klist`) | Le client redemande un TGT à chaque lancement. |
| **Pas de PKINIT** | Authentification initiale possible par certificat (RFC 4556) | Seul le mot de passe est utilisable. |
| Mode **`weak8`** : clés à 8 bits d'entropie (étirées en 16 octets) | Clés aléatoires de 128 ou 256 bits (AES128/256-CTS-HMAC-SHA1 ou SHA2) | Permet de **démontrer** la force brute ; jamais utilisé en vrai. |
| AES-128-**GCM** | AES-**CTS** + HMAC (RFC 3962, RFC 8009) | GCM est plus moderne mais impose de ne jamais réutiliser un nonce. |
| Une seule clé par principal, pas de numéro de version (`kvno`) ni de type de chiffrement négocié | `etype` négocié, `kvno` pour changer les clés sans tout casser | Changer une clé oblige à tout redémarrer. |
| Pas d'adresses, de flags, de `starttime`/`renew-till`, de PAC | Nombreux champs dans le ticket | Ticket minimal : client, clé de session, expiration. |
| Le service n'a que sa clé, mais **lit le même `keys.json`** que le KDC | Chaque service a sa clé dans un *keytab*, le KDC seul a la base | Dans notre démo, compromettre le service revient à compromettre le KDC. |
