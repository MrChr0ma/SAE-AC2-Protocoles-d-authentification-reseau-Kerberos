# Règles de travail

## Branches et pull requests

- On ne pousse pas directement sur `main` : tout passe par une pull request.
- Une branche par sujet, de préférence `feat/<partie>` (`feat/tgs-server`, `feat/service`...). Une branche créée depuis l'interface de GitHub marche aussi.
- Une autre personne du groupe relit la PR avant la fusion. Elle vérifie surtout le contrat des messages ([docs/PROTOCOLE.md](docs/PROTOCOLE.md#contrat-des-messages)).
- Après chaque fusion, chacun récupère `main` sur sa branche (`git pull origin main`).

```bash
git fetch origin
git switch feat/service              # ta branche
git pull origin main                 # récupérer ce qui a été fusionné entre-temps
# ... coder, puis :
pytest
git status                           # keys.json ne doit pas apparaître
git add service/ tests/test_service.py
git commit -m "service: vérifie l'authenticator"
git push
```

Puis ouvrir la PR vers `main` sur GitHub.

- Commits petits, avec un message qui commence par le nom de la partie (`client: ...`, `tgs_server: ...`).
- Une PR touche surtout ton dossier et tes tests. Si elle modifie aussi `common/` ou un autre dossier, dis-le dans la description de la PR.

## Ce qu'on ne modifie pas sans prévenir le groupe

- `common/` (crypto, réseau, configuration) : tout le monde l'utilise.
- Le format des messages : noms des champs, valeurs d'`aad`, quelle clé chiffre quoi. Si l'AS change le contenu du TGT, le TGS ne peut plus l'ouvrir.

Si un changement est nécessaire, préviens le groupe et mets à jour la doc dans la même PR.

## Avant chaque PR

- [ ] `pytest` passe, y compris les tests des autres ;
- [ ] ton programme se lance avec `python -m <dossier>.<fichier>` depuis la racine ;
- [ ] la checklist de ton README est à jour ;
- [ ] `keys.json` n'est pas dans le commit ;
- [ ] une ligne dans [docs/JOURNAL.md](docs/JOURNAL.md) dit ce que tu as fait.

## Style

- Python 3.10+, code en français.
- Commentaires : uniquement une docstring `""" """` par fonction. Pas de commentaires `#` dans le code ; les `# TODO` des squelettes disparaissent quand la partie est codée.
- Toujours chiffrer avec `common.crypto.encrypt` : jamais d'appel direct à `AESGCM` (risque de réutiliser un nonce).
- Toujours utiliser l'heure du serveur (`time.time()`) pour vérifier une expiration ou un timestamp.
