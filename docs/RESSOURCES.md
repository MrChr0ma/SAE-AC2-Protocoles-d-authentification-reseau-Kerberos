# Ressources

Les numéros sont ceux utilisés dans [ANALYSE.md](ANALYSE.md).

## Spécifications de Kerberos

1. RFC 4120, *The Kerberos Network Authentication Service (V5)*, juillet 2005. La référence actuelle, utilisée pour lister les écarts de notre version.
   <https://www.rfc-editor.org/rfc/rfc4120.txt>
2. RFC 1510, *The Kerberos Network Authentication Service (V5)*, septembre 1993. Première spécification de la v5, rendue obsolète par la RFC 4120.
   <https://www.rfc-editor.org/rfc/rfc1510.txt>
3. RFC 3962, *Advanced Encryption Standard (AES) Encryption for Kerberos 5*, février 2005. Les types de chiffrement AES-CTS-HMAC du vrai Kerberos.
   <https://www.rfc-editor.org/rfc/rfc3962.txt>

## Implémentations

4. MIT, *Kerberos: The Network Authentication Protocol*. Page de l'implémentation de référence.
   <https://web.mit.edu/kerberos/>
5. MIT Kerberos Documentation, *krb5.conf*. Valeurs par défaut côté client (`clockskew` de 300 s, durée des tickets).
   <https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html>
6. MIT Kerberos Documentation, *kdc.conf*. Configuration du KDC.
   <https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/kdc_conf.html>
7. Microsoft Learn, *Kerberos authentication overview in Windows Server*. Kerberos dans Windows et Active Directory.
   <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>

## Attaques (MITRE ATT&CK)

8. *Steal or Forge Kerberos Tickets: Golden Ticket* (T1558.001).
   <https://attack.mitre.org/techniques/T1558/001/>
9. *Steal or Forge Kerberos Tickets: Silver Ticket* (T1558.002).
   <https://attack.mitre.org/techniques/T1558/002/>
10. *Steal or Forge Kerberos Tickets: Kerberoasting* (T1558.003).
    <https://attack.mitre.org/techniques/T1558/003/>
11. *Steal or Forge Kerberos Tickets: AS-REP Roasting* (T1558.004). La page dit que la partie de l'AS-REP est « signée » ; d'après la RFC 4120, elle est chiffrée avec la clé du client.
    <https://attack.mitre.org/techniques/T1558/004/>
12. *Use Alternate Authentication Material: Pass the Ticket* (T1550.003).
    <https://attack.mitre.org/techniques/T1550/003/>

## Chiffrement

13. Documentation de `cryptography`, AEAD / `AESGCM`. L'API utilisée dans `common/crypto.py`.
    <https://cryptography.io/en/latest/hazmat/primitives/aead/>
14. Réutilisation de nonce en AES-GCM, conseillée par la référente : pourquoi un nonce ne doit jamais servir deux fois avec la même clé.
    <https://frereit.de/aes_gcm/>
15. Documentation Python, `hashlib.pbkdf2_hmac`. Dérivation de K_client à partir du mot de passe.
    <https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac>
