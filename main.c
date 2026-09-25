#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

// ============================================================================
// Fonction de chiffrement de fichier (avec Padding PKCS#7)
// ============================================================================
void encrypt_file(const char *in_filename, const char *out_filename, const AES_CTX *ctx) {
    FILE *fin = fopen(in_filename, "rb"); // "rb" = Read Binary (Indispensable pour jpg, pdf, mp4)
    FILE *fout = fopen(out_filename, "wb"); // "wb" = Write Binary

    if (!fin || !fout) {
        printf("Erreur : Impossible d'ouvrir les fichiers.\n");
        if(fin) fclose(fin);
        if(fout) fclose(fout);
        return;
    }

    uint8_t buffer[AES_BLOCK_SIZE];
    uint8_t ciphertext[AES_BLOCK_SIZE];
    size_t bytes_read;

    while (1) {
        bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, fin);

        if (bytes_read < AES_BLOCK_SIZE) {
            // Fin du fichier atteinte. On applique le Padding PKCS#7.
            // La valeur du padding est égale au nombre d'octets manquants.
            uint8_t pad_val = AES_BLOCK_SIZE - bytes_read;
            
            for (size_t i = bytes_read; i < AES_BLOCK_SIZE; i++) {
                buffer[i] = pad_val;
            }
            
            AES_encrypt_block(ctx, buffer, ciphertext);
            fwrite(ciphertext, 1, AES_BLOCK_SIZE, fout);
            break; // On sort de la boucle
        } else {
            // Le bloc est complet (16 octets)
            AES_encrypt_block(ctx, buffer, ciphertext);
            fwrite(ciphertext, 1, AES_BLOCK_SIZE, fout);
        }
    }

    fclose(fin);
    fclose(fout);
    printf("Fichier chiffré avec succès : %s\n", out_filename);
}

// ============================================================================
// Fonction de déchiffrement de fichier (avec retrait du Padding PKCS#7)
// ============================================================================
void decrypt_file(const char *in_filename, const char *out_filename, const AES_CTX *ctx) {
    FILE *fin = fopen(in_filename, "rb");
    FILE *fout = fopen(out_filename, "wb");

    if (!fin || !fout) {
        printf("Erreur : Impossible d'ouvrir les fichiers.\n");
        if(fin) fclose(fin);
        if(fout) fclose(fout);
        return;
    }

    uint8_t current_buffer[AES_BLOCK_SIZE];
    uint8_t next_buffer[AES_BLOCK_SIZE];
    uint8_t plaintext[AES_BLOCK_SIZE];
    
    size_t bytes_read = fread(current_buffer, 1, AES_BLOCK_SIZE, fin);

    if (bytes_read == 0) {
        fclose(fin);
        fclose(fout);
        return;
    }

    while (1) {
        // On tente de lire le bloc SUIVANT pour savoir si le bloc ACTUEL est le dernier
        size_t next_bytes_read = fread(next_buffer, 1, AES_BLOCK_SIZE, fin);
        
        AES_decrypt_block(ctx, current_buffer, plaintext);

        if (next_bytes_read == 0) {
            // C'était le tout dernier bloc ! On doit retirer le padding.
            uint8_t pad_val = plaintext[AES_BLOCK_SIZE - 1];
            
            if (pad_val > 0 && pad_val <= AES_BLOCK_SIZE) {
                // On écrit le bloc moins les octets de padding
                fwrite(plaintext, 1, AES_BLOCK_SIZE - pad_val, fout);
            } else {
                printf("Erreur : Padding invalide. Mauvaise clé ou fichier corrompu ?\n");
            }
            break;
        } else {
            // Ce n'est pas le dernier bloc, on l'écrit entièrement
            fwrite(plaintext, 1, AES_BLOCK_SIZE, fout);
            
            // Le bloc "suivant" devient le bloc "actuel" pour le prochain tour
            memcpy(current_buffer, next_buffer, AES_BLOCK_SIZE);
        }
    }

    fclose(fin);
    fclose(fout);
    printf("Fichier déchiffré avec succès : %s\n", out_filename);
}

// ============================================================================
// Programme principal (Utilitaire en ligne de commande)
// ============================================================================
int main(int argc, char *argv[]) {
    // Clé secrète de test (128 bits)
    uint8_t key[AES_KEY_SIZE_128] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    if (argc < 4) {
        printf("Usage : %s <enc|dec> <fichier_entree> <fichier_sortie>\n", argv[0]);
        printf("Exemple : %s enc image.jpg image_chiffree.aes\n", argv[0]);
        printf("Exemple : %s dec image_chiffree.aes image_restauree.jpg\n", argv[0]);
        return 1;
    }

    AES_CTX ctx;
    AES_init_ctx(&ctx, key, AES_128);

    if (strcmp(argv[1], "enc") == 0) {
        encrypt_file(argv[2], argv[3], &ctx);
    } else if (strcmp(argv[1], "dec") == 0) {
        decrypt_file(argv[2], argv[3], &ctx);
    } else {
        printf("Commande inconnue. Utilisez 'enc' pour chiffrer ou 'dec' pour déchiffrer.\n");
    }

    return 0;
}

/* 
// Fonction utilitaire pour afficher les buffers en hexadécimal
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%-12s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    // Vecteurs de test pour AES-128 (issus de l'annexe B du standard FIPS 197)
    uint8_t key[AES_KEY_SIZE_128] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[AES_BLOCK_SIZE] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    AES_CTX ctx;
    
    printf("=== Test d'Implémentation AES-128 ===\n\n");
    print_hex("Clé", key, AES_KEY_SIZE_128);
    print_hex("Texte clair", plaintext, AES_BLOCK_SIZE);
    
    // Initialisation
    AES_init_ctx(&ctx, key, AES_128);

    // Chiffrement
    AES_encrypt_block(&ctx, plaintext, ciphertext);
    print_hex("Chiffré", ciphertext, AES_BLOCK_SIZE);
    // Résultat attendu : 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32

    // Déchiffrement
    AES_decrypt_block(&ctx, ciphertext, decrypted);
    print_hex("Déchiffré", decrypted, AES_BLOCK_SIZE);

    // Vérification
    if (memcmp(plaintext, decrypted, AES_BLOCK_SIZE) == 0) {
        printf("\nSUCCÈS: Le texte déchiffré correspond au texte clair original.\n");
    } else {
        printf("\nERREUR: Le texte déchiffré est différent du texte clair.\n");
    }

    return 0;
}*/