#include <logicalaccess/iks/RPCException.hpp>
#include "logicalaccess/iks/IKSRPCClient.hpp"

namespace logicalaccess
{
    namespace iks
    {

        IKSRPCClient::IKSRPCClient(IslogKeyServer::IKSConfig config) :
                config_(config){
            channel = grpc::CreateChannel("localhost:6565",
                                          grpc::InsecureChannelCredentials());
            stub_ = std::unique_ptr<IKSService::Stub>(IKSService::NewStub(channel));
        }

        ByteVector IKSRPCClient::gen_random(int size) {
            grpc::ClientContext context;
            CMSG_GenRandom req;
            req.set_size(size);

            SMSG_GenRandom rep;
            grpc::Status rpc_status = stub_->GenRandom(&context, req, &rep);
            if (rpc_status.ok())
            {
                return ByteVector(rep.randombytes().begin(), rep.randombytes().end());
            }
            throw RPCException(rpc_status.error_details());
        }
    }
}
