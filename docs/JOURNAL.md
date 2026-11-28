# Journal de bord

Une entrée par étape, la plus récente en bas.

## 17/09/2026 : premier contact

Premier mail du groupe à la référente, Anamaria Costache.

## 25/09/2026 : première réunion

Première réunion du groupe. Ensuite, réunion chaque vendredi à 17h.

## 02/10/2026 : dépôt

Création du dépôt GitHub.

## 09/10/2026 : bibliothèques

Liste des bibliothèques envoyée à la référente pour validation.

## 14/10/2026 : visio de cadrage

Visio avec la référente. On fait une version simplifiée de Kerberos, chaque simplification doit être justifiée dans le rapport. Idée de départ : une clé de 8 bits pour montrer la force brute, en expliquant pourquoi on utilise 128 bits en vrai.

## Semaines du 19/10 et du 26/10 : pause

Pas de travail sur le projet (vacances, puis examens).

## 06/11/2026 : cahier des charges et AES-GCM

Début du cahier des charges dans le Google Doc (partie 1 Denis, partie 2 Enzo, partie 3 Hector, partie 4 Enzo et Hector, partie 5 Sasha). La référente valide AES-GCM avec la bibliothèque `cryptography`, avec une consigne : ne jamais réutiliser un nonce avec la même clé.

## 17/11/2026 : code commun et squelettes

Hector écrit le code commun (`common/`), `scripts/init_keys.py`, les tests et les squelettes des quatre programmes, avec un README par dossier. AES-GCM refusant une clé de 8 bits, on ajoute le mode `weak8` (clés AES-128 avec 256 valeurs possibles).

## 19/11/2026 : répartition du code

Client : Denis. AS : Sasha. TGS : Hector. Service : Enzo.

## 20/11/2026 : client

Client de Denis fusionné (PR n°3).

## 25/11/2026 : AS et vérifications du TGS

AS de Sasha fusionné (PR n°5). Ouverture du TGT et de l'authenticator et vérifications du TGS fusionnées (PR n°4).

## 28/11/2026 : TGS terminé

Replay cache et réponse TGS_REP du TGS fusionnés (PR n°6). Le service d'Enzo est en cours, pas encore fusionné.

## 04/12/2026 : soutenance

Soutenance prévue le vendredi 4 décembre.
