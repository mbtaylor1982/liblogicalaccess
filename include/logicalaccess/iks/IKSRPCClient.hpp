#pragma once

#include "logicalaccess/iks/IslogKeyServer.hpp"
#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include "logicalaccess/iks/packet/iks.grpc.pb.h"

namespace logicalaccess
{
namespace iks
{
/**
 * Wraps a RPC client to IKS.
 */
class IKSRPCClient
{
  public:
    IKSRPCClient(IslogKeyServer::IKSConfig config);

    ByteVector gen_random(int size);

    ByteVector aes_encrypt(const ByteVector &in, const std::string &key_name,
                           const ByteVector &iv);

    ByteVector aes_decrypt(const ByteVector &in, const std::string &key_name,
                           const ByteVector &iv);

    SMSG_DesfireAuth_Step1 desfire_auth_step1(CMSG_DesfireAuth_Step1 req);
    SMSG_DesfireAuth_Step2 desfire_auth_step2(CMSG_DesfireAuth_Step2 req);


  private:
    IslogKeyServer::IKSConfig config_;
    std::shared_ptr<::grpc::ChannelInterface> channel;
    std::unique_ptr<IKSService::Stub> stub_;
};
}
}
