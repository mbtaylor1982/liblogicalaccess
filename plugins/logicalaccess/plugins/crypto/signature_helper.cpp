//
// Created by xaqq on 4/4/18.
//

#include <logicalaccess/plugins/crypto/signature_helper.hpp>
#include <openssl/evp.h>
#include <stdexcept>
#include <openssl/pem.h>

namespace logicalaccess {

    // todo cleanup and fix leak.
    bool SignatureHelper::verify(const std::string &data, const std::string &signature, const std::string &pem_pubkey) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        BIO* bio = BIO_new_mem_buf(pem_pubkey.c_str(), pem_pubkey.size());
        if (bio == nullptr)
        {
            throw std::runtime_error("Cannot wrap pubkey in BIO object");
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

        if (pkey == nullptr)
            throw std::runtime_error("Cannot load public key");

        int type = EVP_PKEY_type(pkey->type);
        if (type != EVP_PKEY_RSA) {
            throw std::runtime_error("Invalid key type");
        }

        if (1 != EVP_DigestVerifyInit(ctx, NULL, EVP_sha512(), NULL, pkey))
        {
            throw std::runtime_error("EVP_DigestVerifyInit");
        }

        /* Initialize `key` with a public key */
        if (1 != EVP_DigestVerifyUpdate(ctx, data.c_str(), data.size()))
        {
            throw std::runtime_error("EVP_DigestVerifyUpdate");
        }

        if (1 == EVP_DigestVerifyFinal(ctx,
                                       reinterpret_cast<const unsigned char *>(signature.c_str()),
                                       signature.size())) {
            return true;
        } else {
            return false;
        }
#else
#endif
        return false;
    }
}
