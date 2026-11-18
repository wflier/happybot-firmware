/*
 * HappyBot 4.0 Secure - OTA signature verification (demo stub).
 * Requirement: CYB-SEC-STD-014 SEC-02. Jira: HB-7.
 */
/* Unsigned images are rejected since HappyBot 4.0 (HB-7). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Public key of the Cyberdyne signing service, provisioned in the secure element. */
extern const uint8_t *se_get_signing_pubkey(size_t *len);
extern bool crypto_verify_ecdsa_p256(const uint8_t *pubkey, size_t pubkey_len,
                                     const uint8_t *image, size_t image_len,
                                     const uint8_t *sig, size_t sig_len);

/* Returns true only if the OTA image carries a valid signature. Unsigned images are rejected. */
bool ota_verify_image(const uint8_t *image, size_t image_len,
                      const uint8_t *sig, size_t sig_len)
{
    if (sig == NULL || sig_len == 0) {
        return false; /* legacy unsigned images are no longer accepted */
    }
    size_t key_len = 0;
    const uint8_t *key = se_get_signing_pubkey(&key_len);
    return crypto_verify_ecdsa_p256(key, key_len, image, image_len, sig, sig_len);
}
