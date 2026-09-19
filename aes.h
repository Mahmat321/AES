#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

// Tailles des clés AES en octets (128, 192, 256 bits)
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

// Taille du bloc de données AES (toujours 128 bits / 16 octets)
#define AES_BLOCK_SIZE 16

// Enumération pour le choix de la taille de clé
typedef enum {
    AES_128,
    AES_192,
    AES_256
} AES_KeySize;

// Contexte AES contenant la clé étendue (Key Schedule)
// La clé étendue nécessite jusqu'à 15 sous-clés (pour AES-256 avec 14 tours)
// 15 * 16 = 240 octets maximum.
typedef struct {
    int rounds;               // Nombre de tours (Nr: 10, 12 ou 14)
    uint8_t round_keys[240];  // Clé étendue
} AES_CTX;

// --- Prototypes des fonctions de l'API ---

// Initialise le contexte AES (Génération du Key Schedule / Expansion de clé)
void AES_init_ctx(AES_CTX *ctx, const uint8_t *key, AES_KeySize key_size);

// Chiffre un bloc de 16 octets
void AES_encrypt_block(const AES_CTX *ctx, const uint8_t *plaintext, uint8_t *ciphertext);

// Déchiffre un bloc de 16 octets
void AES_decrypt_block(const AES_CTX *ctx, const uint8_t *ciphertext, uint8_t *plaintext);

#endif // AES_H