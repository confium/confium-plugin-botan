// Tests for the confium botan plugin: hash + aead (RFC 8452 AES-GCM-SIV
// vectors from Appendix C, plus streaming roundtrips for all supported
// algorithms).

#include <botan/hex.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
uint32_t cfmp_hash_create(void *cfm, void **hash, const char *name, void *opts);
uint32_t cfmp_hash_update(void *hash, const uint8_t *data, uint32_t length);
uint32_t cfmp_hash_finalize(void *hash, uint8_t *result, uint32_t length);
void     cfmp_hash_destroy(void *hash);

uint32_t cfmp_aead_create(const void *cfm, void **aead, const char *algorithm, const void *key,
                          uint32_t key_len, const void *opts);
uint32_t cfmp_aead_set_nonce(void *aead, const uint8_t *nonce, uint32_t length);
uint32_t cfmp_aead_associated_data_update(void *aead, const uint8_t *data, uint32_t length);
uint32_t cfmp_aead_encrypt_update(void *aead, const uint8_t *input, uint32_t input_len,
                                  uint8_t *output, uint32_t *output_len);
uint32_t cfmp_aead_decrypt_update(void *aead, const uint8_t *input, uint32_t input_len,
                                  uint8_t *output, uint32_t *output_len);
uint32_t cfmp_aead_finalize(void *aead, uint8_t *tag, uint32_t tag_max, uint32_t *tag_len);
uint32_t cfmp_aead_verify_tag(void *aead, const uint8_t *tag, uint32_t length);
void     cfmp_aead_destroy(void *aead);
}

static int g_failures = 0;

#define FAIL(fmt, ...)                                     \
    do {                                                   \
        std::printf("FAIL: " fmt "\n", ##__VA_ARGS__);     \
        g_failures++;                                      \
    } while (0)

static const uint32_t CFM_BOTAN_OK = 0;
static const uint32_t CFM_BOTAN_INTEGRITY_FAILURE = 4;

static void
test_hash_sha256()
{
    void *hash = nullptr;
    if (cfmp_hash_create(nullptr, &hash, "SHA-256", nullptr) != CFM_BOTAN_OK || hash == nullptr) {
        FAIL("hash_create SHA-256 failed");
        return;
    }
    const char *msg = "abc";
    cfmp_hash_update(hash, (const uint8_t *) msg, std::strlen(msg));
    uint8_t digest[32];
    if (cfmp_hash_finalize(hash, digest, sizeof(digest)) != CFM_BOTAN_OK) {
        FAIL("hash_finalize failed");
    } else {
        auto expect = Botan::hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        if (std::memcmp(digest, expect.data(), expect.size()) != 0) {
            FAIL("SHA-256(\"abc\") digest mismatch");
        }
    }
    cfmp_hash_destroy(hash);
}

// RFC 8452 Appendix C test data. `Out` is the tag (16 bytes) followed by
// the ciphertext.
struct RfcVector {
    const char *algo;
    const char *key;
    const char *nonce;
    const char *ad;
    const char *pt;
    const char *out;
};

static const RfcVector rfc8452_vectors[] = {
  // AES-128-GCM-SIV
  { "AES-128-GCM-SIV",
    "01000000000000000000000000000000",
    "030000000000000000000000",
    "",
    "",
    "DC20E2D83F25705BB49E439ECA56DE25" },
  { "AES-128-GCM-SIV",
    "01000000000000000000000000000000",
    "030000000000000000000000",
    "",
    "0100000000000000",
    "B5D839330AC7B786578782FFF6013B815B287C22493A364C" },
  { "AES-128-GCM-SIV",
    "01000000000000000000000000000000",
    "030000000000000000000000",
    "01",
    "0200000000000000",
    "1E6DABA35669F4273B0A1A2560969CDF790D99759ABD1508" },
  // AES-256-GCM-SIV
  { "AES-256-GCM-SIV",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "030000000000000000000000",
    "",
    "0100000000000000",
    "C2EF328E5C71C83B843122130F7364B761E0B97427E3DF28" },
};

static void
run_encrypt_vector(const RfcVector &v)
{
    auto key = Botan::hex_decode(v.key);
    auto nonce = Botan::hex_decode(v.nonce);
    auto ad = Botan::hex_decode(v.ad);
    auto pt = Botan::hex_decode(v.pt);
    auto out = Botan::hex_decode(v.out);
    auto expect_tag = std::vector<uint8_t>(out.begin(), out.begin() + 16);
    auto expect_ct = std::vector<uint8_t>(out.begin() + 16, out.end());

    void *aead = nullptr;
    if (cfmp_aead_create(nullptr, &aead, v.algo, key.data(), key.size(), nullptr) != CFM_BOTAN_OK ||
        aead == nullptr) {
        FAIL("%s: create failed", v.algo);
        return;
    }
    cfmp_aead_set_nonce(aead, nonce.data(), nonce.size());
    if (!ad.empty()) {
        cfmp_aead_associated_data_update(aead, ad.data(), ad.size());
    }

    // SIV modes emit no ciphertext on update; it drains after finalize
    std::vector<uint8_t> ct;
    std::vector<uint8_t> chunk(64);
    uint32_t n = chunk.size();
    if (cfmp_aead_encrypt_update(aead, pt.data(), pt.size(), chunk.data(), &n) != CFM_BOTAN_OK) {
        FAIL("%s: encrypt_update failed", v.algo);
    }
    uint8_t tag[16];
    uint32_t tag_len = sizeof(tag);
    if (cfmp_aead_finalize(aead, tag, sizeof(tag), &tag_len) != CFM_BOTAN_OK ||
        tag_len != 16 ||
        std::memcmp(tag, expect_tag.data(), 16) != 0) {
        FAIL("%s: tag mismatch", v.algo);
    }
    n = chunk.size();
    if (cfmp_aead_encrypt_update(aead, nullptr, 0, chunk.data(), &n) != CFM_BOTAN_OK) {
        FAIL("%s: ciphertext drain failed", v.algo);
    }
    ct.assign(chunk.begin(), chunk.begin() + n);
    if (ct != expect_ct) {
        FAIL("%s: ciphertext mismatch", v.algo);
    }
    cfmp_aead_destroy(aead);
}

static void
run_decrypt_vector(const RfcVector &v)
{
    auto key = Botan::hex_decode(v.key);
    auto nonce = Botan::hex_decode(v.nonce);
    auto ad = Botan::hex_decode(v.ad);
    auto pt = Botan::hex_decode(v.pt);
    auto out = Botan::hex_decode(v.out);
    auto tag = std::vector<uint8_t>(out.begin(), out.begin() + 16);
    auto ct = std::vector<uint8_t>(out.begin() + 16, out.end());

    void *aead = nullptr;
    if (cfmp_aead_create(nullptr, &aead, v.algo, key.data(), key.size(), nullptr) != CFM_BOTAN_OK ||
        aead == nullptr) {
        FAIL("%s: create failed", v.algo);
        return;
    }
    cfmp_aead_set_nonce(aead, nonce.data(), nonce.size());
    if (!ad.empty()) {
        cfmp_aead_associated_data_update(aead, ad.data(), ad.size());
    }

    std::vector<uint8_t> drained(64);
    uint32_t n = drained.size();
    if (cfmp_aead_decrypt_update(aead, ct.data(), ct.size(), drained.data(), &n) != CFM_BOTAN_OK) {
        FAIL("%s: decrypt_update failed", v.algo);
    }
    if (cfmp_aead_verify_tag(aead, tag.data(), tag.size()) != CFM_BOTAN_OK) {
        FAIL("%s: verify_tag rejected a valid tag", v.algo);
    }
    n = drained.size();
    if (cfmp_aead_decrypt_update(aead, nullptr, 0, drained.data(), &n) != CFM_BOTAN_OK ||
        n != pt.size() || std::memcmp(drained.data(), pt.data(), n) != 0) {
        FAIL("%s: drained plaintext mismatch", v.algo);
    }
    cfmp_aead_destroy(aead);
}

static void
test_rfc8452_vectors()
{
    for (const auto &v : rfc8452_vectors) {
        run_encrypt_vector(v);
        run_decrypt_vector(v);
    }
}

// streaming roundtrip: encrypt in three chunks, decrypt in three chunks
// (with the SIV drain step), then confirm a tampered tag is rejected.
static void
test_roundtrip(const char *algo, uint32_t key_len, bool siv)
{
    std::vector<uint8_t> key(key_len);
    for (uint32_t i = 0; i < key_len; i++) {
        key[i] = (uint8_t) (i * 7 + 1);
    }
    std::vector<uint8_t> nonce(12);
    for (uint32_t i = 0; i < 12; i++) {
        nonce[i] = (uint8_t) (i * 3);
    }
    std::vector<uint8_t> aad = { 'h', 'e', 'a', 'd', 'e', 'r' };
    std::vector<uint8_t> pt(43);
    for (uint32_t i = 0; i < pt.size(); i++) {
        pt[i] = (uint8_t) (i * 11 + 5);
    }

    void *enc = nullptr;
    void *dec = nullptr;
    if (cfmp_aead_create(nullptr, &enc, algo, key.data(), key.size(), nullptr) != CFM_BOTAN_OK ||
        enc == nullptr ||
        cfmp_aead_create(nullptr, &dec, algo, key.data(), key.size(), nullptr) != CFM_BOTAN_OK ||
        dec == nullptr) {
        FAIL("%s: create failed", algo);
        return;
    }
    cfmp_aead_set_nonce(enc, nonce.data(), nonce.size());
    cfmp_aead_associated_data_update(enc, aad.data(), aad.size());
    cfmp_aead_set_nonce(dec, nonce.data(), nonce.size());
    cfmp_aead_associated_data_update(dec, aad.data(), aad.size());

    std::vector<uint8_t> ct;
    std::vector<uint8_t> chunk(64);
    for (uint32_t off = 0; off < pt.size(); off += 16) {
        uint32_t len = std::min<uint32_t>(16, pt.size() - off);
        uint32_t n = chunk.size();
        if (cfmp_aead_encrypt_update(enc, pt.data() + off, len, chunk.data(), &n) != CFM_BOTAN_OK ||
            n != (siv ? 0u : len)) {
            FAIL("%s: encrypt_update chunk failed", algo);
        }
        ct.insert(ct.end(), chunk.begin(), chunk.begin() + n);
    }
    uint8_t tag[16];
    uint32_t tag_len = sizeof(tag);
    if (cfmp_aead_finalize(enc, tag, sizeof(tag), &tag_len) != CFM_BOTAN_OK || tag_len != 16) {
        FAIL("%s: finalize failed", algo);
    }
    if (siv) {
        // SIV ciphertext drains through zero-length encrypt_update calls
        uint32_t n = chunk.size();
        while (cfmp_aead_encrypt_update(enc, nullptr, 0, chunk.data(), &n) == CFM_BOTAN_OK &&
               n > 0) {
            ct.insert(ct.end(), chunk.begin(), chunk.begin() + n);
            n = chunk.size();
        }
    }
    cfmp_aead_destroy(enc);

    std::vector<uint8_t> rt;
    for (uint32_t off = 0; off < ct.size(); off += 16) {
        uint32_t len = std::min<uint32_t>(16, ct.size() - off);
        uint32_t n = chunk.size();
        if (cfmp_aead_decrypt_update(dec, ct.data() + off, len, chunk.data(), &n) != CFM_BOTAN_OK) {
            FAIL("%s: decrypt_update chunk failed", algo);
        }
        rt.insert(rt.end(), chunk.begin(), chunk.begin() + n);
    }
    if (cfmp_aead_verify_tag(dec, tag, tag_len) != CFM_BOTAN_OK) {
        FAIL("%s: verify_tag rejected a valid tag", algo);
    }
    uint32_t n = chunk.size();
    if (cfmp_aead_decrypt_update(dec, nullptr, 0, chunk.data(), &n) != CFM_BOTAN_OK) {
        FAIL("%s: drain failed", algo);
    }
    rt.insert(rt.end(), chunk.begin(), chunk.begin() + n);
    if (rt.size() != pt.size() || rt != pt) {
        FAIL("%s: roundtrip plaintext mismatch (%zu vs %zu bytes)", algo, rt.size(), pt.size());
    }

    // a flipped tag bit must be rejected
    cfmp_aead_destroy(dec);
    if (cfmp_aead_create(nullptr, &dec, algo, key.data(), key.size(), nullptr) != CFM_BOTAN_OK) {
        FAIL("%s: create failed", algo);
        return;
    }
    std::vector<uint8_t> bad(tag, tag + sizeof(tag));
    bad[0] ^= 0x80;
    cfmp_aead_set_nonce(dec, nonce.data(), nonce.size());
    cfmp_aead_associated_data_update(dec, aad.data(), aad.size());
    n = chunk.size();
    cfmp_aead_decrypt_update(dec, ct.data(), ct.size(), chunk.data(), &n);
    if (cfmp_aead_verify_tag(dec, bad.data(), bad.size()) != CFM_BOTAN_INTEGRITY_FAILURE) {
        FAIL("%s: tampered tag not rejected", algo);
    }
    cfmp_aead_destroy(dec);
}

static void
test_unknown_algorithm()
{
    void *aead = (void *) (uintptr_t) 0x1;
    if (cfmp_aead_create(nullptr, &aead, "AES-192-OCB", nullptr, 0, nullptr) != CFM_BOTAN_OK ||
        aead != nullptr) {
        FAIL("unknown algorithm must report no offer, got a handle");
    }
}

int
main()
{
    test_hash_sha256();
    test_rfc8452_vectors();
    test_roundtrip("AES-128-GCM-SIV", 16, true);
    test_roundtrip("AES-256-GCM-SIV", 32, true);
    test_roundtrip("AES-256-GCM", 32, false);
    test_roundtrip("ChaCha20-Poly1305", 32, false);
    test_unknown_algorithm();

    if (g_failures > 0) {
        std::printf("%d test(s) FAILED\n", g_failures);
        return 1;
    }
    std::printf("all tests passed\n");
    return 0;
}
