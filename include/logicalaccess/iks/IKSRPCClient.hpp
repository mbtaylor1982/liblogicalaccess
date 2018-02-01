#pragma once

#include "logicalaccess/iks/IslogKeyServer.hpp"
#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include "logicalaccess/iks/packet/iks.grpc.pb.h"

namespace logicalaccess {
    namespace iks {
        /**
         * Wraps a RPC client to IKS.
         */
        class IKSRPCClient {
        public:
            IKSRPCClient(IslogKeyServer::IKSConfig config);

            IKSService::Stub &api()
            {
                return *stub_.get();
            }

            ByteVector gen_random(int size);

        private:
            IslogKeyServer::IKSConfig config_;
            std::shared_ptr<::grpc::ChannelInterface> channel;
            std::unique_ptr<IKSService::Stub> stub_;
        };

    }
}
