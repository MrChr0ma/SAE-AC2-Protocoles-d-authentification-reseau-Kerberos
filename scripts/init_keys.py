"""Génère keys.json : la « base de données » des clés long terme du KDC.

Usage (depuis la racine du dépôt) :
    python scripts/init_keys.py --password motdepasse
    KRB_KEY_MODE=weak8 python scripts/init_keys.py --password motdepasse

Contenu produit (clés en hexadécimal) :
    {
      "alice":  K_client  = derive_key(mot de passe, "alice"),
      "krbtgt": K_tgs     = nouvelle clé aléatoire,
      "mail":   K_service = nouvelle clé aléatoire
    }

Dans un vrai Kerberos, seul le KDC possède ce fichier (sa base de comptes),
et chaque service ne connaît que sa propre clé (fichier « keytab »).
Ici tout le monde lit le même fichier : c'est une simplification.

keys.json est dans .gitignore : il ne doit jamais être committé.
Relancer le script remplace toutes les clés : il faut alors redémarrer
l'AS, le TGS et le service.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Le script est lancé avec `python scripts/init_keys.py` : on ajoute la racine
# du dépôt au chemin d'import pour pouvoir importer common.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common import config  # noqa: E402
from common.crypto import derive_key, new_session_key  # noqa: E402


def build_keys(password: str, client: str = config.DEFAULT_CLIENT) -> dict[str, bytes]:
    """Construit le dictionnaire des clés long terme."""
    keys = {
        client: derive_key(password, client),
        config.TGS_PRINCIPAL: new_session_key(),
    }
    for service in config.SERVICES:
        keys[service] = new_session_key()
    return keys


def main() -> None:
    parser = argparse.ArgumentParser(description="Génère keys.json (clés long terme du KDC).")
    parser.add_argument("--password", required=True, help="mot de passe du client")
    parser.add_argument("--client", default=config.DEFAULT_CLIENT,
                        help=f"nom du client (défaut : {config.DEFAULT_CLIENT})")
    parser.add_argument("--output", default=str(config.KEYS_FILE),
                        help=f"fichier de sortie (défaut : {config.KEYS_FILE})")
    args = parser.parse_args()

    keys = build_keys(args.password, args.client)
    output = Path(args.output)
    output.write_text(
        json.dumps({name: key.hex() for name, key in keys.items()}, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(output, 0o600)  # lisible par son propriétaire seulement (sans effet sous Windows)
    except OSError:
        pass

    print(f"{output} écrit (mode de clé : {config.KEY_MODE})")
    for name, key in keys.items():
        print(f"  {name:8s} {len(key)} octets")
    print("Pense à (re)démarrer l'AS, le TGS et le service.")


if __name__ == "__main__":
    main()
