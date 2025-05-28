/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>     
#include <inttypes.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_system.h"
#include "driver/uart.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#include "mbedtls/aes.h"
#include "esp_mac.h"
#include <stdlib.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#define BUF_SIZE 1024

static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

const char PUBLIC_KEY_LAPTOP[] = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA09TsSdNLpV795nYgdMER\nJmVcGE5atV/f1DqXwTT+BkmIjemAR71JrNbEKjK1Tp9vqOx2W/jXgljb40ddzMZn\ng53VFinjHY+Vln1EUisSN1nEVNUG/prYLWq+aNCuM2XCXm5gn5W5ndnSxSQx+6QM\nISby6ow/4HZuHM8NPQYwCavDXsZpwKyeXhdaKTcFSq/8jhCZEycFeKtKX5fDnfn2\nXiF0W2K/nbUusttdqNXmz357DgzBdh2eJljx/LfXTW4Y85XGvpb003reTnrONDud\nItYaLS2xyQw+lLwacRRnA7c3S6ydqcWsGzaPS09g5ZY4In708/Al/WDs+cIWbz3B\nvwIDAQAB\n-----END PUBLIC KEY-----\n";

const char PUBLIC_KEY_MCU[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzmDgtldyvpc73W3/JZtj\n"
"VIOGEoOyt7ou3n7PjipThNHKb8VfnFob+b5c15BAZc4GHHadA7hYZI/ZkWXqTraZ\n"
"wrnx/9c6UjDZeeqIZqqZbPJ3ZWJ4vF8z/5Uy5k2ygeU9jXlAhsJAdDpVe24A6YeC\n"
"wqwgxrqMQTLywhg3tWRziPDZdRiuwoMEaglZ9gNZoxCgir0PGOEBVTJlp/3WNt/V\n"
"cm0geqO1fqA+zF7hd2f3VezMKDo/7MxvvGba6XC75ttzioznZnJATJPOI3avwwGL\n"
"7fkiHjwDBoFMck7Ro0udTnRWycMg3gsAqAxD7IxOEYeMQ3JXmVz0G+pjof80sM4C\n"
"wQIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const char PRIVATE_KEY_MCU[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOYOC2V3K+lzvd\n"
"bf8lm2NUg4YSg7K3ui7efs+OKlOE0cpvxV+cWhv5vlzXkEBlzgYcdp0DuFhkj9mR\n"
"ZepOtpnCufH/1zpSMNl56ohmqpls8ndlYni8XzP/lTLmTbKB5T2NeUCGwkB0OlV7\n"
"bgDph4LCrCDGuoxBMvLCGDe1ZHOI8Nl1GK7CgwRqCVn2A1mjEKCKvQ8Y4QFVMmWn\n"
"/dY239VybSB6o7V+oD7MXuF3Z/dV7MwoOj/szG+8ZtrpcLvm23OKjOdmckBMk84j\n"
"dq/DAYvt+SIePAMGgUxyTtGjS51OdFbJwyDeCwCoDEPsjE4Rh4xDcleZXPQb6mOh\n"
"/zSwzgLBAgMBAAECggEAAmp+jeNhFsDM2jHgNWadK8oHPwdGGKYoHSP9zb1OrSkG\n"
"kfKzax9GmLti/X0beX0YTXQIn7I1W+ZJJKtKHWY3rVxSmzfiDnwqFKpgw+hi71If\n"
"iVU5VKW97/Gt2IwgaCH7b+dvKhj3XQgqH+uaeG4z+HYmoRPh1BYJJyEajKbKFA/S\n"
"GeU+IvbyCT43TJmpLLLoE5qcVVWojUv/Mp0YXK89JtbfVHQY10B8Fh5zXZfDWReC\n"
"p3yV0LhtioMbUl9VlCo/gH5y7oLB8gStqFAXFI7DaAeobqIOWyf/QLTbumyfVi2+\n"
"RYulnmx1B65bR3qLUj/24qj1PWa3IQu8HHI+dP6r1QKBgQDmjn/n9ANt1palYa9G\n"
"DioFz4aCuHMohEnEI52/RNozj6dr+ej83+7l12/J+dF9vg96h2dLJ/Ez1lF8Oi/p\n"
"3oQh3vKVKhWvQmBiJYJDhPhHTmUXoxlcQy1oXktAnXORENrI+K+GZ5irKiCi4+lJ\n"
"TqrzWDKcaMtgTcfgS9DBKtxW9QKBgQDlJ1CZC+DK6qF3frmqkNSpNZB42k/Mbe+Z\n"
"2DrcGQLvJ716qycOR6PQu7gDUQ4Ww1QKj/GUxlUWeC7oJf6Y0aMw1X1cZgH0lpu/\n"
"WLyvVto/roLO6BVvnotwZG/MdLZdiMcT/C5WQ5d1oOqJHUAAPet2PI5qxXO+DNVB\n"
"DwYafHPlHQKBgCoe3IU+0iWN76W1K/VLfyfimvtkwT0ktelMbHRWGtsSoo6acJNK\n"
"QfXhnv2yUzB6uY80D43udSV4QRjF9JzwVwltFrpjnuSO5tbnbV3ye/1i+BsSY/60\n"
"EyafG3ZpjYRyJNZUgJS4dm7G2oGHy8XlxluAwHZMuuMUMrDqiO/RacHFAoGBAOQh\n"
"C6ARryzUAQNRac1gehYqeTWXQTInkAz8szxCuiUUzxG8KhmRQIihGURUAU6wDo6l\n"
"Vr/h4vuHkksS6C+DJI+NOkwuUWwKM+t+j/mO4Z/cP+V0L0L7951gn9xPpO3hKS/A\n"
"MvE2QSadmGAAeqLDAhKnnrC0+dEOPY+TQWRE2awRAoGAKIcrgMn1SLV6o1NYFNiw\n"
"OuLP+Pn2BMSA6abJZT0eJXQpqp3b3KPeZBHYpw21mn2raDfzFVFV2T6FzUNJrPUA\n"
"E2ixNLo0XWLkfD/2p+8muCrYdFRxHvXDD0Nf33VQ6zoRo4a+Lg+Vf2Ja1x7HuVvu\n"
"AThq/JuEgjZ/+1XcOTQRlAA=\n"
"-----END PRIVATE KEY-----\n";

void compute_sha256(const unsigned char *input, size_t len, unsigned char output[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, input, len);
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

void init_uart() {
    const uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_driver_install(UART_NUM_0, BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_NUM_0, &uart_config);
    uart_set_pin(UART_NUM_0, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
}
// void restart_esp() {
//     esp_restart();
// }
bool verify_signature(const char *message, const char *base64_signature) {
    int ret;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Parse the PEM public key
    ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)PUBLIC_KEY_LAPTOP, strlen(PUBLIC_KEY_LAPTOP) + 1);
    if (ret != 0) {
        printf("Failed to parse public key! mbedtls_pk_parse_public_key returned -0x%04X\n", -ret);
        return false;
    }

    // Compute SHA-256 hash of message
    unsigned char hash[32];
    compute_sha256((unsigned char *)message, strlen(message), hash);

    // Decode Base64 signature
    unsigned char sig[512];
    size_t sig_len = 0;
    ret = mbedtls_base64_decode(sig, sizeof(sig), &sig_len, (const unsigned char *)base64_signature, strlen(base64_signature));
    if (ret != 0) {
        printf("Base64 decode failed! mbedtls_base64_decode returned -0x%04X\n", -ret);
        mbedtls_pk_free(&pk);
        return false;
    }

    // Verify the signature
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, sig, sig_len);
    mbedtls_pk_free(&pk);

    if (ret == 0) {
        return true;
    } else {
        printf("Signature verification failed! mbedtls_pk_verify returned -0x%04X\n", -ret);
        return false;
    }
}

// int dummy_rng(void *ctx, unsigned char *buf, size_t len) {
//     (void)ctx;
//     (void)buf;
//     (void)len;
//     return 0;
// }

unsigned char* decrypt_aes_key_with_rsa(const char* enc_key_b64, size_t* out_len) {
    int ret;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Parse the private key
    ret = mbedtls_pk_parse_key(&pk, (const unsigned char*)PRIVATE_KEY_MCU, strlen(PRIVATE_KEY_MCU) + 1, NULL, 0, NULL, NULL);
    if (ret != 0) {
        printf("Failed to parse private key! mbedtls_pk_parse_key returned -0x%04X\n", -ret);
        return NULL;
    }

    // Base64 decode the encrypted AES key
    size_t b64_len = strlen(enc_key_b64);
    unsigned char* enc_key = malloc(256);
    if (!enc_key) {
        printf("Failed to allocate memory for encrypted AES key.\n");
        mbedtls_pk_free(&pk);
        return NULL;
    }

    size_t enc_key_len = 0;
    ret = mbedtls_base64_decode(enc_key, 256, &enc_key_len, (const unsigned char*)enc_key_b64, b64_len);
    printf("enc_key_b64: %s\n", enc_key_b64);
    if (ret != 0) {
        printf("Base64 decode failed for AES key! mbedtls_base64_decode returned -0x%04X\n", -ret);
        free(enc_key);
        mbedtls_pk_free(&pk);
        return NULL;
    }

    if (enc_key_len != 256) {
        printf("ERROR: Encrypted AES key length is %zu, expected 256 bytes!\n", enc_key_len);
        free(enc_key);
        mbedtls_pk_free(&pk);
        return NULL;
    }

    // Allocate buffer for decrypted AES key (AES-256 = 32 bytes)
    unsigned char* decrypted_key = malloc(32);
    if (!decrypted_key) {
        printf("Failed to allocate memory for decrypted AES key.\n");
        free(enc_key);
        mbedtls_pk_free(&pk);
        return NULL;
    }

    size_t decrypted_key_len = 0;
    ret = mbedtls_pk_decrypt(&pk, enc_key, enc_key_len, decrypted_key, &decrypted_key_len, 32, mbedtls_ctr_drbg_random, &ctr_drbg);

    free(enc_key);
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        printf("AES key RSA decryption failed! mbedtls_pk_decrypt returned -0x%04X\n", -ret);
        free(decrypted_key);
        return NULL;
    }

    if (decrypted_key_len != 32) {
        printf("ERROR: Decrypted AES key length is %zu, expected 32 bytes!\n", decrypted_key_len);
        free(decrypted_key);
        return NULL;
    }

    printf("AES key successfully decrypted.\n");
    *out_len = decrypted_key_len;
    return decrypted_key;
}

unsigned char* decrypt_aes_payload(const char* iv_b64, const char* enc_payload_b64, const unsigned char* aes_key, size_t* out_len) {
    // Decode IV
    unsigned char iv[16];
    size_t iv_len = 0;
    int ret = mbedtls_base64_decode(iv, sizeof(iv), &iv_len, (const unsigned char*)iv_b64, strlen(iv_b64));
    if (ret != 0 || iv_len != 16) {
        printf("Invalid IV decode.\n");
        return NULL;
    }

    // Decode Encrypted Payload
    unsigned char enc_payload[1024];
    size_t enc_payload_len = 0;
    ret = mbedtls_base64_decode(enc_payload, sizeof(enc_payload), &enc_payload_len, (const unsigned char*)enc_payload_b64, strlen(enc_payload_b64));
    if (ret != 0) {
        printf("Invalid encrypted payload decode.\n");
        return NULL;
    }

    // Decrypt
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aes_key, 256);

    unsigned char* decrypted = malloc(enc_payload_len);
    if (!decrypted) return NULL;

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, enc_payload_len, iv, enc_payload, decrypted);
    mbedtls_aes_free(&aes);
    if (ret != 0) {
        printf("AES decryption failed.\n");
        free(decrypted);
        return NULL;
    }

    // Remove PKCS#7 padding
    size_t pad = decrypted[enc_payload_len - 1];
    if (pad > 16 || pad == 0) {
        printf("Invalid padding.\n");
        free(decrypted);
        return NULL;
    }
    *out_len = enc_payload_len - pad;
    decrypted[*out_len] = '\0';
    return decrypted;
}

void app_main(void)
{
    uint8_t data[BUF_SIZE];
    char current_message[256] = "Hello world!";
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    // printf("Hello world!\n");

    //Chip information      
    esp_chip_info_t chip_info;
    uint32_t flash_size;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU core(s), %s%s%s%s, ",
           "ESP32 ",
           chip_info.cores,
           (chip_info.features & CHIP_FEATURE_WIFI_BGN) ? "WiFi/" : "",
           (chip_info.features & CHIP_FEATURE_BT) ? "BT" : "",
           (chip_info.features & CHIP_FEATURE_BLE) ? "BLE" : "",
           (chip_info.features & CHIP_FEATURE_IEEE802154) ? ", 802.15.4 (Zigbee/Thread)" : "");

    unsigned major_rev = chip_info.revision / 100;
    unsigned minor_rev = chip_info.revision % 100;
    printf("silicon revision v%d.%d, ", major_rev, minor_rev);

    if (esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        printf("Get flash size failed\n");
        return;
    }

    printf("%" PRIu32 "MB %s flash\n", flash_size / (1024 * 1024),
           (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    printf("Minimum free heap size: %" PRIu32 " bytes\n", esp_get_minimum_free_heap_size());
    
    init_uart();

    printf("Listening for secure string update...\n");

    while (1) {
        //printf("Waiting for data...\n");
        printf("Current message: %s\n", current_message);
        int len = uart_read_bytes(UART_NUM_0, data, BUF_SIZE - 1, pdMS_TO_TICKS(1000));
        printf("Data length: %d\n", len);
        if (len > 0) {
            data[len] = '\0';

            // Format expected: <enc_aes_key>::<iv>::<enc_payload>
            char *ptr1 = strstr((char *)data, "::");
            if (!ptr1) {
                printf("Invalid format. Missing first '::'\n");
                continue;
            }
            *ptr1 = '\0';
            char *enc_key_b64 = (char *)data;

            char *ptr2 = strstr(ptr1 + 2, "::");
            if (!ptr2) {
                printf("Invalid format. Missing second '::'\n");
                continue;
            }
            *ptr2 = '\0';
            char *iv_b64 = ptr1 + 2;
            char *enc_payload_b64 = ptr2 + 2;

            size_t aes_key_len;
            unsigned char* aes_key = decrypt_aes_key_with_rsa(enc_key_b64, &aes_key_len);
            if (!aes_key) {
                printf("AES key decryption failed. Skipping...\n");
                continue;
            }

            // Decrypt AES payload to get the original message::signature
            size_t decrypted_len;
            unsigned char* decrypted_payload = decrypt_aes_payload(iv_b64, enc_payload_b64, aes_key, &decrypted_len);
            free(aes_key);

            if (!decrypted_payload) {
                printf("Payload decryption failed.\n");
                continue;
            }

            // Split decrypted_payload into <message>::<signature>
            char *sep = strstr((char *)decrypted_payload, "::");
            if (!sep) {
                printf("Decrypted payload format invalid.\n");
                free(decrypted_payload);
                continue;
            }
            *sep = '\0';
            char *message = (char *)decrypted_payload;
            char *recv_hash = sep + 2;

            if (verify_signature(message, recv_hash)) {
                strncpy(current_message, message, sizeof(current_message) - 1);
                current_message[sizeof(current_message) - 1] = '\0';
                printf("Signature verified. Message updated!\n");
            } else {
                printf("Invalid signature. Ignoring message.\n");
            }

            free(decrypted_payload);
        }
        printf("Current message: %s\n", current_message);
        vTaskDelay(pdMS_TO_TICKS(5000));  
    }
}