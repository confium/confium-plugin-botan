#include <botan/aead.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/secmem.h>
#include <stdint.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#define PUBLICAPI __attribute__((visibility("default")))

// plugin-local status codes returned by the cfmp_aead_* entry points
enum {
    CFM_BOTAN_OK = 0,
    CFM_BOTAN_ERROR = 1,             // generic exception, details on stderr
    CFM_BOTAN_UNSUPPORTED_ALGORITHM = 2,
    CFM_BOTAN_INVALID_INPUT = 3,     // bad key/nonce/tag size or call order
    CFM_BOTAN_INTEGRITY_FAILURE = 4, // authentication tag mismatch
    CFM_BOTAN_BUFFER_TOO_SMALL = 5,
};

static uint32_t
ffi_exception(FILE *fp, const char *func, const char *msg, uint32_t ret = CFM_BOTAN_ERROR)
{
    fprintf(fp, "[%s()] Error 0x%08X: %s\n", func, ret, msg);
    return ret;
}

#define FFI_GUARD_FP(fp)                                           \
    catch (std::exception & e)                                     \
    {                                                              \
        return ffi_exception((fp), __func__, e.what());            \
    }                                                              \
    catch (...)                                                    \
    {                                                              \
        return ffi_exception((fp), __func__, "unknown exception"); \
    }

#define FFI_GUARD FFI_GUARD_FP((stderr))

struct Confium;
struct Options;
struct Hash;
struct Aead;

extern "C" {
PUBLICAPI uint32_t cfmp_interface_version(Confium *cfm);
PUBLICAPI uint32_t cfmp_initialize(Confium *cfm, const Options *opts);
PUBLICAPI uint32_t cfmp_finalize(Confium *cfm);

PUBLICAPI const uint8_t *cfmp_query_interfaces(Confium *cfm);

PUBLICAPI uint32_t cfmp_hash_create(Confium *   cfm,
                                    Hash **     hash,
                                    const char *name,
                                    Options *   opts);
PUBLICAPI uint32_t cfmp_hash_output_size(Hash *hash, uint32_t *size);
PUBLICAPI uint32_t cfmp_hash_block_size(Hash *hash, uint32_t *size);
PUBLICAPI uint32_t cfmp_hash_update(Hash *hash, const uint8_t *data, uint32_t length);
PUBLICAPI uint32_t cfmp_hash_reset(Hash *hash);
PUBLICAPI uint32_t cfmp_hash_clone(Hash *src, Hash **dst);
PUBLICAPI uint32_t cfmp_hash_finalize(Hash *hash, uint8_t *result, uint32_t length);
PUBLICAPI void     cfmp_hash_destroy(Hash *hash);

PUBLICAPI uint32_t cfmp_aead_create(const Confium * cfm,
                                    Aead **         aead,
                                    const char *    algorithm,
                                    const void *    key,
                                    uint32_t        key_len,
                                    const Options * opts);
PUBLICAPI uint32_t cfmp_aead_set_nonce(Aead *aead, const uint8_t *nonce, uint32_t length);
PUBLICAPI uint32_t cfmp_aead_associated_data_update(Aead *aead, const uint8_t *data, uint32_t length);
PUBLICAPI uint32_t cfmp_aead_encrypt_update(Aead *       aead,
                                            const uint8_t *input,
                                            uint32_t     input_len,
                                            uint8_t *    output,
                                            uint32_t *   output_len);
PUBLICAPI uint32_t cfmp_aead_decrypt_update(Aead *       aead,
                                            const uint8_t *input,
                                            uint32_t     input_len,
                                            uint8_t *    output,
                                            uint32_t *   output_len);
PUBLICAPI uint32_t cfmp_aead_finalize(Aead *aead, uint8_t *tag, uint32_t tag_max, uint32_t *tag_len);
PUBLICAPI uint32_t cfmp_aead_verify_tag(Aead *aead, const uint8_t *tag, uint32_t length);
PUBLICAPI void     cfmp_aead_destroy(Aead *aead);
}

uint32_t
cfmp_interface_version(Confium *cfm)
{
    return 0;
}

uint32_t
cfmp_initialize(Confium *cfm, const Options *opts)
{
    return 0;
}

uint32_t
cfmp_finalize(Confium *cfm)
{
    return 0;
}

const uint8_t *
cfmp_query_interfaces(Confium *cfm)
{
    // packed `name + NUL + version_byte + NUL` byte stream
    static const uint8_t interfaces[] = {
      'h',   'a',   's',   'h',   '\0',  0x00,  '\0',
      'a',   'e',   'a',   'd',   '\0',  0x00,  '\0',
    };
    return interfaces;
}

/*
 * hash interface
 */

uint32_t
cfmp_hash_create(Confium *cfm, Hash **hash, const char *name, Options *opts)
try {
    auto obj = Botan::HashFunction::create(name).release();
    *hash = (Hash *) obj;
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_hash_output_size(Hash *hash, uint32_t *size)
try {
    auto obj = (Botan::HashFunction *) hash;
    *size = obj->output_length();
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_hash_block_size(Hash *hash, uint32_t *size)
try {
    auto obj = (Botan::HashFunction *) hash;
    *size = obj->hash_block_size();
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_hash_update(Hash *hash, const uint8_t *data, uint32_t length)
try {
    auto obj = (Botan::HashFunction *) hash;
    obj->update(data, length);
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_hash_reset(Hash *hash)
try {
    auto obj = (Botan::HashFunction *) hash;
    obj->clear();
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_hash_clone(Hash *src, Hash **dst)
try {
    auto obj = (Botan::HashFunction *) src;
    *dst = (Hash *) obj->copy_state().release();
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_hash_finalize(Hash *hash, uint8_t *result, uint32_t length)
try {
    auto obj = (Botan::HashFunction *) hash;
    if (length < obj->output_length()) {
        return CFM_BOTAN_BUFFER_TOO_SMALL;
    }
    Botan::secure_vector<uint8_t> digest;
    obj->final(digest);
    std::copy(digest.begin(), digest.end(), result);
    return CFM_BOTAN_OK;
}
FFI_GUARD

void
cfmp_hash_destroy(Hash *hash)
{
    auto obj = (Botan::HashFunction *) hash;
    delete obj;
}

/*
 * aead interface
 *
 * The Confium name of each supported algorithm maps to a Botan
 * specification string. `siv` marks nonce-misuse-resistant modes whose
 * decryption cannot produce plaintext until the authentication tag is
 * known: on the decrypt side every update is buffered, and the
 * plaintext produced by verify_tag is drained through a subsequent
 * decrypt_update call with a zero-length input.
 */

struct AeadAlgoInfo {
    const char *confium_name;
    const char *botan_spec;
    bool        siv;
};

static const AeadAlgoInfo
aead_algorithms[] = {
  { "AES-128-GCM-SIV", "AES-128/GCM-SIV", true },
  { "AES-256-GCM-SIV", "AES-256/GCM-SIV", true },
  { "AES-256-GCM", "AES-256/GCM", false },
  { "ChaCha20-Poly1305", "ChaCha20Poly1305", false },
};

static const AeadAlgoInfo *
aead_algorithm_of(const char *name)
{
    if (name == nullptr) {
        return nullptr;
    }
    for (const auto &entry : aead_algorithms) {
        if (std::strcmp(entry.confium_name, name) == 0) {
            return &entry;
        }
    }
    return nullptr;
}

struct Aead {
    const AeadAlgoInfo *           algo = nullptr;
    Botan::secure_vector<uint8_t>  key;
    Botan::secure_vector<uint8_t>  nonce;
    Botan::secure_vector<uint8_t>  aad;
    std::unique_ptr<Botan::AEAD_Mode> mode;
    bool                           started = false;
    Botan::secure_vector<uint8_t>  buf;     // non-SIV decrypt-side staging
    // SIV modes cannot emit anything until the whole message (and, for
    // decryption, the tag) is known: stream_buf accumulates plaintext
    // (encrypt) or ciphertext (decrypt); pending holds ciphertext
    // (encrypt) or plaintext (decrypt) awaiting a zero-length update.
    Botan::secure_vector<uint8_t>  stream_buf;
    Botan::secure_vector<uint8_t>  pending;
};

static uint32_t
aead_start(Aead *a, Botan::Cipher_Dir dir)
try {
    if (a->mode != nullptr) {
        return CFM_BOTAN_OK;
    }
    if (a->nonce.empty()) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    a->mode = Botan::AEAD_Mode::create(a->algo->botan_spec, dir);
    if (a->mode == nullptr) {
        return CFM_BOTAN_UNSUPPORTED_ALGORITHM;
    }
    if (!a->mode->valid_keylength(a->key.size())) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (!a->mode->valid_nonce_length(a->nonce.size())) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    a->mode->set_key(a->key);
    if (!a->aad.empty()) {
        a->mode->set_associated_data(a->aad);
    }
    a->mode->start(a->nonce);
    a->started = true;
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_aead_create(const Confium *cfm,
                 Aead **        aead,
                 const char *   algorithm,
                 const void *   key,
                 uint32_t       key_len,
                 const Options *opts)
try {
    if (aead == nullptr) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    *aead = nullptr;
    auto algo = aead_algorithm_of(algorithm);
    if (algo == nullptr) {
        // report "not offered" so the runtime can try other providers
        return CFM_BOTAN_OK;
    }
    if (key == nullptr && key_len != 0) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    auto obj = new Aead();
    obj->algo = algo;
    auto key_bytes = (const uint8_t *) key;
    obj->key.assign(key_bytes, key_bytes + key_len);
    *aead = (Aead *) obj;
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_aead_set_nonce(Aead *aead, const uint8_t *nonce, uint32_t length)
try {
    auto obj = (Aead *) aead;
    if (obj->mode != nullptr) {
        // one message per instance
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (nonce == nullptr && length != 0) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    obj->nonce.assign(nonce, nonce + length);
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_aead_associated_data_update(Aead *aead, const uint8_t *data, uint32_t length)
try {
    auto obj = (Aead *) aead;
    if (obj->mode != nullptr) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (data == nullptr && length != 0) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (length == 0) {
        return CFM_BOTAN_OK;
    }
    obj->aad.insert(obj->aad.end(), data, data + length);
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_aead_encrypt_update(Aead *        aead,
                         const uint8_t *input,
                         uint32_t      input_len,
                         uint8_t *     output,
                         uint32_t *    output_len)
try {
    auto obj = (Aead *) aead;
    if (output_len == nullptr || (input == nullptr && input_len != 0) ||
        (output == nullptr && input_len != 0)) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (uint32_t code = aead_start(obj, Botan::Cipher_Dir::Encryption)) {
        return code;
    }
    if (obj->algo->siv) {
        // SIV cannot produce ciphertext until the whole message is known
        if (input_len == 0) {
            uint32_t n = std::min<uint32_t>(obj->pending.size(), *output_len);
            if (n > 0) {
                std::copy(obj->pending.begin(), obj->pending.begin() + n, output);
                obj->pending.erase(obj->pending.begin(), obj->pending.begin() + n);
            }
            *output_len = n;
            return CFM_BOTAN_OK;
        }
        obj->stream_buf.insert(obj->stream_buf.end(), input, input + input_len);
        *output_len = 0;
        return CFM_BOTAN_OK;
    }
    Botan::secure_vector<uint8_t> buf(input, input + input_len);
    obj->mode->update(buf);
    if (buf.size() > *output_len) {
        return CFM_BOTAN_BUFFER_TOO_SMALL;
    }
    std::copy(buf.begin(), buf.end(), output);
    *output_len = buf.size();
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_aead_decrypt_update(Aead *        aead,
                         const uint8_t *input,
                         uint32_t      input_len,
                         uint8_t *     output,
                         uint32_t *    output_len)
try {
    auto obj = (Aead *) aead;
    if (output_len == nullptr) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (input_len == 0) {
        // zero-length input drains plaintext produced by verify_tag
        uint32_t n = std::min<uint32_t>(obj->pending.size(), *output_len);
        if (n > 0) {
            std::copy(obj->pending.begin(), obj->pending.begin() + n, output);
            obj->pending.erase(obj->pending.begin(), obj->pending.begin() + n);
        }
        *output_len = n;
        return CFM_BOTAN_OK;
    }
    if (input == nullptr || (output == nullptr)) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (uint32_t code = aead_start(obj, Botan::Cipher_Dir::Decryption)) {
        return code;
    }
    if (obj->algo->siv) {
        // SIV cannot decrypt until the tag (via verify_tag) is known
        obj->stream_buf.insert(obj->stream_buf.end(), input, input + input_len);
        *output_len = 0;
        return CFM_BOTAN_OK;
    }
    obj->buf.insert(obj->buf.end(), input, input + input_len);
    obj->mode->update(obj->buf);
    uint32_t n = std::min<uint32_t>(obj->buf.size(), *output_len);
    std::copy(obj->buf.begin(), obj->buf.begin() + n, output);
    *output_len = n;
    obj->buf.clear();
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_aead_finalize(Aead *aead, uint8_t *tag, uint32_t tag_max, uint32_t *tag_len)
try {
    auto obj = (Aead *) aead;
    if (tag_len == nullptr) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (obj->mode == nullptr || !obj->started) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (obj->algo->siv) {
        // RFC 8452 output layout: tag (16) followed by the ciphertext
        obj->mode->finish(obj->stream_buf);
        if (obj->stream_buf.size() < 16) {
            return CFM_BOTAN_ERROR;
        }
        if (16 > tag_max) {
            return CFM_BOTAN_BUFFER_TOO_SMALL;
        }
        std::copy_n(obj->stream_buf.begin(), 16, tag);
        *tag_len = 16;
        obj->pending.assign(obj->stream_buf.begin() + 16, obj->stream_buf.end());
        obj->stream_buf.clear();
        return CFM_BOTAN_OK;
    }
    Botan::secure_vector<uint8_t> out;
    obj->mode->finish(out);
    if (out.size() > tag_max) {
        return CFM_BOTAN_BUFFER_TOO_SMALL;
    }
    std::copy(out.begin(), out.end(), tag);
    *tag_len = out.size();
    return CFM_BOTAN_OK;
}
FFI_GUARD

uint32_t
cfmp_aead_verify_tag(Aead *aead, const uint8_t *tag, uint32_t length)
try {
    auto obj = (Aead *) aead;
    if (tag == nullptr && length != 0) {
        return CFM_BOTAN_INVALID_INPUT;
    }
    if (uint32_t code = aead_start(obj, Botan::Cipher_Dir::Decryption)) {
        return code;
    }
    if (obj->algo->siv) {
        // RFC 8452 message layout: tag (16) followed by the ciphertext
        obj->buf = obj->stream_buf;
        obj->buf.insert(obj->buf.begin(), tag, tag + length);
        obj->mode->finish(obj->buf);
        obj->pending.swap(obj->buf);
        obj->stream_buf.clear();
        return CFM_BOTAN_OK;
    }
    obj->buf.insert(obj->buf.end(), tag, tag + length);
    obj->mode->finish(obj->buf);
    obj->pending.insert(obj->pending.end(), obj->buf.begin(), obj->buf.end());
    obj->buf.clear();
    return CFM_BOTAN_OK;
}
catch (Botan::Integrity_Failure & e) {
    return ffi_exception(stderr, __func__, e.what(), CFM_BOTAN_INTEGRITY_FAILURE);
}
FFI_GUARD

void
cfmp_aead_destroy(Aead *aead)
{
    auto obj = (Aead *) aead;
    delete obj;
}
