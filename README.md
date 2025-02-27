# Projet de wallet HD pour bitcoin en Rust

Génération de la seed BIP39 du wallet avec pbkdf2, donc 2048 tours de hmac-sha512 sur la mnémonique et la passe phrase
Ensuite géréation de la master key avec BIP32 (private key + code de chaine de dérivation) en fonction de la dérivation utilisé.

## Dérivations
- BIP44
- BIP49
- BIP84

## À venir
- Gestion des adresses
- signature (Taproot, P2PK, ...)