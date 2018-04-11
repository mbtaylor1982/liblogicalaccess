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
struct SignatureResult;

/**
 * Wraps a RPC client to IKS.
 */
class IKSRPCClient
{
  public:
    explicit IKSRPCClient(IslogKeyServer::IKSConfig config);

    ByteVector gen_random(int size);

    ByteVector aes_encrypt(const ByteVector &in, const std::string &key_name,
                           const ByteVector &iv);

    ByteVector aes_decrypt(const ByteVector &in, const std::string &key_name,
                           const ByteVector &iv,
                           SignatureResult *out_signature = nullptr);

    SMSG_DesfireISOAuth_Step1 desfire_auth_iso_step1(CMSG_DesfireISOAuth_Step1 req);
    SMSG_DesfireAuth_Step2 desfire_auth_iso_step2(CMSG_DesfireAuth_Step2 req);

    SMSG_DesfireAESAuth_Step1 desfire_auth_aes_step1(CMSG_DesfireAESAuth_Step1 req);
    SMSG_DesfireAuth_Step2 desfire_auth_aes_step2(CMSG_DesfireAuth_Step2 req);

    SMSG_DesfireChangeKey desfire_change_key(CMSG_DesfireChangeKey req);

  private:
    IslogKeyServer::IKSConfig config_;
    std::shared_ptr<::grpc::ChannelInterface> channel;
    std::unique_ptr<IKSService::Stub> stub_;
};
}
}
