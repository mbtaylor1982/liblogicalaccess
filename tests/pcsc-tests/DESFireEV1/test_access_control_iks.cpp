#include <logicalaccess/cards/IKSStorage.hpp>
#include <logicalaccess/dynlibrary/idynlibrary.hpp>
#include <logicalaccess/dynlibrary/librarymanager.hpp>
#include <logicalaccess/readerproviders/readerconfiguration.hpp>
#include <logicalaccess/readerproviders/serialportdatatransport.hpp>
#include <logicalaccess/services/accesscontrol/accesscontrolcardservice.hpp>
#include <logicalaccess/services/accesscontrol/formats/customformat/numberdatafield.hpp>
#include <logicalaccess/services/accesscontrol/formats/wiegand26format.hpp>
#include <logicalaccess/services/accesscontrol/formats/wiegand37format.hpp>
#include <logicalaccess/services/storage/storagecardservice.hpp>
#include <logicalaccess/plugins/cards/desfire/nxpav2keydiversification.hpp>

#include <logicalaccess/plugins/cards/desfire/desfireev1chip.hpp>
#include <logicalaccess/plugins/cards/desfire/desfireev1location.hpp>
#include <logicalaccess/plugins/cards/desfire/desfireev1commands.hpp>
#include <logicalaccess/plugins/cards/desfire/nxpav1keydiversification.hpp>
#include <logicalaccess/plugins/readers/iso7816/commands/desfireev1iso7816commands.hpp>
#include <logicalaccess/iks/IslogKeyServer.hpp>

#include <logicalaccess/plugins/lla-tests/macros.hpp>
#include <logicalaccess/plugins/lla-tests/utils.hpp>
#include <logicalaccess/services/accesscontrol/formats/rawformat.hpp>
#include <logicalaccess/services/accesscontrol/formats/customformat/customformat.hpp>
#include <logicalaccess/iks/RPCException.hpp>

void introduction()
{
    PRINT_TIME("This test target DESFireEV1 cards. It tests that we are "
               "can read data from a card w/o knowing the session key");

    PRINT_TIME("You will have 20 seconds to insert a card. Test log below");
    PRINT_TIME("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}

ByteVector vector_from_string(const std::string &s)
{
    ByteVector ret(s.begin(), s.end());
    return ret;
}

int main(int ac, char **av)
{
    using namespace logicalaccess;
    prologue(ac, av);
    introduction();
    ReaderProviderPtr provider;
    ReaderUnitPtr readerUnit;
    ChipPtr chip;
    tie(provider, readerUnit, chip) = lla_test_init();

    iks::IslogKeyServer::configureGlobalInstance(
        "iksf", 6565, "/home/xaqq/Documents/iks/crypto/arnaud.pem",
        "/home/xaqq/Documents/iks/crypto/arnaud.key",
        "/home/xaqq/Documents/iks/crypto/MyRootCA.pem");

    PRINT_TIME("Chip identifier: "
               << logicalaccess::BufferHelper::getHex(chip->getChipIdentifier()));

    LLA_ASSERT(chip->getCardType() == "DESFireEV1" || chip->getCardType() == "DESFireEV2",
               "Chip is not an DESFireEV{1,2}, but is " + chip->getCardType() +
                   " instead.");

    auto storage =
        std::dynamic_pointer_cast<StorageCardService>(chip->getService(CST_STORAGE));
    std::shared_ptr<AccessControlCardService> acs =
        std::dynamic_pointer_cast<AccessControlCardService>(
            chip->getService(CST_ACCESS_CONTROL));

    auto fmt = std::make_shared<RawFormat>();
    // Yeah we need this hack to specify the size we need.
    fmt->setRawData(ByteVector(4, 0));
    auto loc   = std::make_shared<DESFireLocation>();
    loc->aid   = 0x000521;
    loc->file  = 0;
    loc->byte_ = 0;

    std::shared_ptr<DESFireKey> key(new DESFireKey());
    key->setKeyType(DF_KEY_AES);
    // key->fromString("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    // key->setKeyStorage(std::make_shared<IKSStorage>("d852a915-7435-464d-9fbf-680d056c827b"));
    // key->setKeyStorage(std::make_shared<IKSStorage>("df30845a-3ca4-40ab-91f4-f45cb2e37b67"));
    // auto kst = std::make_shared<IKSStorage>("36ff2fbc-dcf5-413b-a274-b9531fdbd9c");
    // auto kst = std::make_shared<IKSStorage>("12c856a2-969a-4bad-a9c0-37b09ca69304");
    // KEY EV 2 !!!
    auto div = std::make_shared<NXPAV2KeyDiversification>();
    div->setSystemIdentifier(ByteVector{0x94, 0x56});
    auto kst = std::make_shared<IKSStorage>("660557b6-846c-4cfe-bd38-027c6bb98f3b");
    key->setKeyDiversification(div);

    // key->fromString("4a 9b 22 a6 b0 01 d2 9f 4e c8 a0 02 66 e0 06 b2");
    key->setKeyStorage(kst);
    auto ai       = std::make_shared<DESFireAccessInfo>();
    ai->readKey   = key;
    ai->readKeyno = 1;

    try
    {
        auto fmt_result = acs->readFormat(fmt, loc, ai);

        if (!fmt_result)
        {
            std::cout << "Failed to read access information." << std::endl;
            return -1;
        }

        std::cout << "Read data: " << fmt_result->getLinearData() << std::endl;
        auto sig_res = acs->IKS_getPayloadSignature();
        std::cout << "Signature: " << BufferHelper::getHex(sig_res.signature_)
                  << std::endl;
        std::cout << "Signature Description: \n"
                  << "\tNonce: " << sig_res.signature_description_.nonce() << std::endl
                  << "\tTimestamp: " << sig_res.signature_description_.timestamp()
                  << std::endl
                  << "\tPayload: "
                  << BufferHelper::getHex(sig_res.signature_description_.payload())
                  << std::endl
                  << "\tRun UUID: "
                  << BufferHelper::getHex(sig_res.signature_description_.run_uuid())
                  << std::endl;

        std::cout << "DescriptionBlob: "
                  << BufferHelper::getHex(
                         sig_res.signature_description_.SerializeAsString())
                  << std::endl;
    }
    catch (const iks::RPCException &e)
    {
        std::cerr << "Something went wrong: " << e.what() << std::endl;
    }

    return 0;
}
