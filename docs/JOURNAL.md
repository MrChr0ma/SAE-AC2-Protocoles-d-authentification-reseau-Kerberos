# Journal de bord

Ce journal sert de base au rapport et aux slides. On y note, au fil du projet, les décisions prises, leur justification, les difficultés et ce qu'on a appris. Une entrée par séance ou par étape importante, la plus récente en bas.

Modèle d'entrée :

```
## AAAA-MM-JJ : titre court

**Qui** : ...
**Fait** : ...
**Décisions** : ... (et pourquoi)
**Difficultés** : ...
**À faire ensuite** : ...
```

---

## 2026-10-14 : visio avec la prof (cadrage)

**Qui** : le groupe 19 et Anamaria Costache (visio, 17h45).

**Décisions** :
- On implémente une **version simplifiée** de Kerberos : il n'est pas nécessaire de reprendre tous les détails de la RFC. Liberté sur le reste, à condition de justifier les choix.
- L'objectif pédagogique est de faire travailler **l'esprit critique** : chaque simplification doit être assumée, et le rapport doit expliquer ce qui manque pour une vraie implémentation.
- Idée de départ : une clé de 8 bits « par simplicité », en expliquant pourquoi en vrai c'est 128 bits.
- Point de départ conseillé : la page Wikipédia de Kerberos.
- Faire valider avec la prof les choix de ressources (bibliothèques) et ce qu'on fait.
- Langage : C ou Python acceptés.
- Démonstration envisagée : un programme avec deux personnes, l'une obtient un ticket, l'autre le vérifie.
- Rapport qui suit le projet au fil du cours, puis slides pour la soutenance. Noter les idées dès le début dans un Google Doc.

## Cahier des charges et choix techniques (date à compléter)

**Fait** :
- Rédaction du **cahier des charges** dans le Google Doc : contexte, périmètre, fonctionnement et algorithme, choix techniques, tests, livrables, répartition de la rédaction.
- Choix de **Python** (C envisagé) : plus rapide à écrire et à lire pour tout le groupe, bibliothèques de chiffrement fiables, `socket` et `threading` dans la bibliothèque standard. À justifier dans le rapport.

**Décisions** :
- Bibliothèque **`cryptography`** avec **AES-GCM** (`AESGCM`), **validée par la prof**, avec une consigne explicite : **ne jamais réutiliser un nonce avec la même clé** (référence : <https://frereit.de/aes_gcm/>).
- AES-GCM n'accepte pas de clé de 8 bits : on garde des clés AES-128 et on ajoute un mode `weak8` où les clés n'ont que 256 valeurs possibles, pour démontrer la force brute.

## 2026-11-17 : mise en place du dépôt

**Fait** :
- Structure du dépôt en 5 parties (client, AS, TGS, service, code commun), une branche par partie.
- Code commun écrit et testé : `common/crypto.py` (PBKDF2, AES-GCM avec nonce aléatoire à chaque chiffrement, `aad` par rôle, mode `weak8`), `common/net.py` (messages JSON préfixés par leur longueur, serveur multi-thread), `common/config.py`, `scripts/init_keys.py`.
- Squelettes commentés des quatre programmes, qui se lancent et répondent « non implémenté ».
- README détaillé pour chaque partie, contrat des messages dans `docs/PROTOCOLE.md`.

**Décisions** :
- AS et TGS en deux programmes séparés (dans la réalité, un seul KDC), qui lisent tous deux K_tgs dans `keys.json`.
- `aad` différent pour chaque type de chiffré, pour qu'un chiffré ne puisse pas être présenté à la place d'un autre.
- Replay cache côté TGS et service, en plus de la fenêtre de 5 minutes.
- Les scripts d'attaque sont reportés à plus tard (pistes dans `docs/ANALYSE.md`).

**À faire ensuite** : chaque personne code sa partie ; intégration client + AS, puis TGS, puis service.
