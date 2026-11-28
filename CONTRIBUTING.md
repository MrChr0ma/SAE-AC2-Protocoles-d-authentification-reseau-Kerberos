# Règles de travail

## Une branche par partie

| Partie | Branche |
| --- | --- |
| 1. Client | `feat/client` |
| 2. AS | `feat/as-server` |
| 3. TGS | `feat/tgs-server` |
| 4. Service | `feat/service` |
| 5. Code commun | `feat/common` |

On ne pousse jamais directement sur `main` : tout passe par une pull request.

## Workflow

```bash
git fetch origin
git switch feat/as-server            # ta branche
git pull origin main                 # récupérer ce qui a été fusionné entre-temps
# ... coder, puis :
pytest
git add as_server/ tests/test_as_server.py
git commit -m "as_server: génère le TGT"
git push
```

Puis ouvrir une PR de ta branche vers `main` sur GitHub. La personne 5 (code commun) relit en priorité le respect du contrat des messages ; au moins une autre personne relit aussi.

- Commits petits, avec un message clair qui commence par le nom de la partie (`client: ...`, `tgs_server: ...`).
- Ne touche qu'à ton dossier et à tes tests dans `tests/`.
- Avant chaque `git add`, vérifie avec `git status` que `keys.json` n'apparaît pas.

## Ce qu'on ne modifie pas sans prévenir le groupe

- **`common/`** (crypto, réseau, configuration) : il est utilisé par tout le monde. Une modification se discute d'abord avec la personne 5, puis passe par `feat/common` et une PR à part.
- **Le format des messages** ([docs/PROTOCOLE.md](docs/PROTOCOLE.md#contrat-des-messages)) : noms des champs, valeurs d'`aad`, ce qui est chiffré avec quelle clé. Si l'AS change le contenu du TGT, le TGS ne peut plus l'ouvrir.

Si tu as besoin d'un changement, préviens le groupe, mets à jour la doc en même temps que le code.

## Avant chaque PR

- [ ] `pytest` passe (y compris les tests des autres) ;
- [ ] ton programme se lance avec `python -m <dossier>.<fichier>` depuis la racine ;
- [ ] la checklist de ton README est à jour (cases cochées) ;
- [ ] `keys.json` n'est pas dans le commit ;
- [ ] tu as noté dans [docs/JOURNAL.md](docs/JOURNAL.md) ce que tu as fait et les difficultés rencontrées (utile pour le rapport).

## Ordre d'intégration

1. **Client (échange 1) + AS** : le client obtient un TGT et l'affiche.
2. **TGS** : le client obtient un ticket de service.
3. **Service** : authentification mutuelle complète.

Après chaque fusion dans `main`, tout le monde fait `git pull origin main` sur sa branche.

## Style

- Python 3.10+, code en français.
- Commentaires : uniquement une docstring `""" """` par fonction. Pas de commentaires `#` dans le code ; les `# TODO` des squelettes disparaissent quand la partie est codée.
- Toujours chiffrer avec `common.crypto.encrypt` : jamais d'appel direct à `AESGCM` (risque de réutiliser un nonce).
- Toujours utiliser l'heure du serveur (`time.time()`) pour vérifier une expiration ou un timestamp.
