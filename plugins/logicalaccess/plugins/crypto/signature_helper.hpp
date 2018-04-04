//
// Created by xaqq on 4/4/18.
//

#ifndef LIBLOGICALACCESS_SIGNATURE_HELPER_HPP
#define LIBLOGICALACCESS_SIGNATURE_HELPER_HPP


#include <string>

namespace logicalaccess {

    /**
     * Some static pubkey based signature utils.
     */
    class SignatureHelper {
    public:
        /**
         * Verify that the signature of `data` matches `signature`.
         *
         * pem_pubkey is a text PEM encoded public to use for signature verification.
         *
         * @param data
         * @param signature
         * @param pem_pubkey
         * @return true if signature is valid, false otherwise.
         */
        static bool verify(const std::string &data, const std::string &signature, const std::string &pem_pubkey);
    };

}

#endif //LIBLOGICALACCESS_SIGNATURE_HELPER_HPP
