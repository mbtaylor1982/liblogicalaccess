#include <logicalaccess/iks/RPCException.hpp>
#include "logicalaccess/iks/IKSRPCClient.hpp"
#include <chrono>

namespace logicalaccess
{
namespace iks
{
IKSRPCClient::IKSRPCClient(IslogKeyServer::IKSConfig config)
    : config_(config)
{
    // Configure gRPC ssl from IKSConfig.
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_cert_chain  = config.get_client_cert_pem();
    ssl_opts.pem_private_key = config.get_client_key_pem();
    ssl_opts.pem_root_certs  = config.get_root_ca_pem();

    channel = grpc::CreateChannel(config.get_target(), grpc::SslCredentials(ssl_opts));
    auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(10000);
    channel->WaitForConnected(deadline);
    stub_ = std::unique_ptr<IKSService::Stub>(IKSService::NewStub(channel));
}

ByteVector IKSRPCClient::gen_random(int size)
{
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

ByteVector IKSRPCClient::aes_encrypt(const ByteVector &in, const std::string &key_name,
                                     const ByteVector &iv)
{
    grpc::ClientContext context;
    CMSG_AESOperation req;
    req.set_key_name(key_name);
    req.set_payload(std::string(in.begin(), in.end()));
    req.set_iv(std::string(iv.begin(), iv.end()));

    SMSG_AESResult rep;
    grpc::Status rpc_status = stub_->AESEncrypt(&context, req, &rep);
    if (rpc_status.ok())
    {
        return ByteVector(rep.payload().begin(), rep.payload().end());
    }
    throw RPCException(rpc_status.error_message() + ": " + rpc_status.error_details());
}

ByteVector IKSRPCClient::aes_decrypt(const ByteVector &in, const std::string &key_name,
                                     const ByteVector &iv)
{
    grpc::ClientContext context;
    CMSG_AESOperation req;
    req.set_key_name(key_name);
    req.set_payload(std::string(in.begin(), in.end()));
    req.set_iv(std::string(iv.begin(), iv.end()));

    SMSG_AESResult rep;
    grpc::Status rpc_status = stub_->AESDecrypt(&context, req, &rep);
    if (rpc_status.ok())
    {
        return ByteVector(rep.payload().begin(), rep.payload().end());
    }
    throw RPCException(rpc_status.error_message() + ": " + rpc_status.error_details());
}

SMSG_DesfireAuth_Step1 IKSRPCClient::desfire_auth_step1(CMSG_DesfireAuth_Step1 req)
{
    grpc::ClientContext context;

    SMSG_DesfireAuth_Step1 rep;
    grpc::Status rpc_status = stub_->DESFireAuth1(&context, req, &rep);
    if (rpc_status.ok())
    {
        return rep;
    }
    throw RPCException(rpc_status.error_message() + ": " + rpc_status.error_details());
}

SMSG_DesfireAuth_Step2 IKSRPCClient::desfire_auth_step2(CMSG_DesfireAuth_Step2 req)
{
    grpc::ClientContext context;

    SMSG_DesfireAuth_Step2 rep;
    grpc::Status rpc_status = stub_->DESFireAuth2(&context, req, &rep);
    if (rpc_status.ok())
    {
        return rep;
    }
    throw RPCException(rpc_status.error_message() + ": " + rpc_status.error_details());
}
}
}
