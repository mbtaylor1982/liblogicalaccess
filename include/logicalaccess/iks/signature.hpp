#pragma once

#include "logicalaccess/lla_fwd.hpp"

namespace logicalaccess
{
    namespace iks
    {
        /**
         * An object describing a signature issued by IKS.
         *
         * The object contains both the original signed payload aswell as
         * signature parameter and the signature itself.
         */
        struct SignatureResult {

            bool verify(ByteVector server_pubkey);

            ByteVector payload_;
            uint64_t nonce_;
            uint64_t timestamp_;
            ByteVector run_uuid_;
        };
    }
}