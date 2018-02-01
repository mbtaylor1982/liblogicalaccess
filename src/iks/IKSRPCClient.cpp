#include <logicalaccess/iks/RPCException.hpp>
#include "logicalaccess/iks/IKSRPCClient.hpp"
#include <chrono>

namespace logicalaccess
{
    namespace iks
    {

        IKSRPCClient::IKSRPCClient(IslogKeyServer::IKSConfig config) :
                config_(config){
            // Configure gRPC ssl from IKSConfig.
            grpc::SslCredentialsOptions ssl_opts;
            ssl_opts.pem_cert_chain = config.get_client_cert_pem();
            ssl_opts.pem_private_key = config.get_client_key_pem();
            ssl_opts.pem_root_certs = config.get_root_ca_pem();

            channel = grpc::CreateChannel(config.get_target(),
                                          grpc::SslCredentials(ssl_opts));
            auto deadline = std::chrono::system_clock::now() +
                            std::chrono::milliseconds(10000);
            channel->WaitForConnected(deadline);
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
            throw RPCException(rpc_status.error_message() + ": " + rpc_status.error_details());
        }
    }
}
