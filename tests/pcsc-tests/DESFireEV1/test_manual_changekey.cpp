#include <logicalaccess/dynlibrary/idynlibrary.hpp>
#include <logicalaccess/dynlibrary/librarymanager.hpp>
#include <logicalaccess/readerproviders/readerconfiguration.hpp>
#include <logicalaccess/services/storage/storagecardservice.hpp>
#include <logicalaccess/services/accesscontrol/formats/wiegand26format.hpp>
#include <logicalaccess/services/accesscontrol/formats/wiegand37format.hpp>
#include <logicalaccess/services/accesscontrol/formats/customformat/numberdatafield.hpp>
#include <logicalaccess/readerproviders/serialportdatatransport.hpp>
#include <logicalaccess/services/accesscontrol/accesscontrolcardservice.hpp>
#include <logicalaccess/plugins/cards/desfire/desfireev1chip.hpp>
#include <logicalaccess/plugins/readers/iso7816/commands/desfireev1iso7816commands.hpp>
#include <logicalaccess/plugins/cards/desfire/desfirecommands.hpp>

#include <logicalaccess/plugins/lla-tests/macros.hpp>
#include <logicalaccess/plugins/lla-tests/utils.hpp>

void introduction()
{
    PRINT_TIME("This test target DESFireEV1 cards.");

    PRINT_TIME("You will have 20 seconds to insert a card. Test log below");
    PRINT_TIME("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}

void create_app_and_file(std::shared_ptr<logicalaccess::DESFireISO7816Commands> cmd,
                         std::shared_ptr<logicalaccess::DESFireEV1ISO7816Commands> cmdev1)
{
    // create the application we wish to write into
    cmdev1->createApplication(0x535, logicalaccess::DESFireKeySettings::KS_DEFAULT, 3,
                              logicalaccess::DESFireKeyType::DF_KEY_AES,
                              logicalaccess::FIDS_NO_ISO_FID, 0, ByteVector());
    cmd->selectApplication(0x535);

    std::shared_ptr<logicalaccess::DESFireKey> key(new logicalaccess::DESFireKey());
    key->setKeyType(logicalaccess::DESFireKeyType::DF_KEY_AES);
    key->fromString("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    ByteVector bla(key->getData(), key->getData() + key->getLength());

    using namespace logicalaccess;
    cmd->authenticate(0, key);

    std::shared_ptr<DESFireKey> new_key(new DESFireKey());
    new_key->fromString("11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11");
    new_key->setKeyType(DF_KEY_AES);

    // We can do everything with key1
    DESFireAccessRights ar;
    ar.readAccess         = AR_KEY0;
    ar.writeAccess        = AR_KEY0;
    ar.readAndWriteAccess = AR_KEY0;
    ar.changeAccess       = AR_KEY0;

    // Create the file we will use.
    int file_size = 16;
    cmdev1->createStdDataFile(0x00, CM_ENCRYPT, ar, file_size, 0);
    cmd->authenticate(0, key);

    std::shared_ptr<DESFireChip> dchip =
        std::dynamic_pointer_cast<DESFireChip>(cmd->getChip());
    dchip->getCrypto()->setKey(0x535, 0, 0, key);

    cmd->changeKey(0, new_key);
}

int main(int ac, char **av)
{
    using namespace logicalaccess;
    prologue(ac, av);
    introduction();
    ReaderProviderPtr provider;
    ReaderUnitPtr readerUnit;
    ChipPtr chip;
    tie(provider, readerUnit, chip) = lla_test_init("DESFireEV1");

    PRINT_TIME("CHip identifier: "
               << logicalaccess::BufferHelper::getHex(chip->getChipIdentifier()));

    LLA_ASSERT(chip->getCardType() == "DESFireEV1",
               "Chip is not an DESFireEV1, but is " + chip->getCardType() + " instead.");

    std::shared_ptr<DESFireEV1Chip> desfirechip =
        std::dynamic_pointer_cast<DESFireEV1Chip>(chip);
    assert(desfirechip);
    PRINT_TIME("Has Real UID: " << desfirechip->hasRealUID());

    auto location_root_node = chip->getRootLocationNode();

    auto cmd = std::dynamic_pointer_cast<DESFireISO7816Commands>(chip->getCommands());
    auto cmdev1 =
        std::dynamic_pointer_cast<DESFireEV1ISO7816Commands>(chip->getCommands());
    LLA_ASSERT(cmd && cmdev1, "Cannot get correct command object from chip.");


    std::shared_ptr<DESFireKey> key(new DESFireKey());
    key->fromString("11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11");
    key->setKeyType(DF_KEY_AES);

    std::shared_ptr<DESFireKey> newkey(new DESFireKey());
    newkey->setKeyType(DF_KEY_AES);
    newkey->fromString("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

    cmd->selectApplication(0x00);
    cmd->authenticate(0);
    std::cout << "Auth 0000" << std::endl;

    cmd->erase();
    std::cout << "Erased..." << std::endl;

    cmdev1->createApplication(0x521, KS_DEFAULT, 3, DF_KEY_AES, FIDS_NO_ISO_FID, 0,
                              ByteVector());

    std::cout << "Created 0x521" << std::endl;

    cmd->selectApplication(0x521);
    cmd->authenticate(0, newkey);
    LLA_SUBTEST_PASSED("Authenticate");
    /*
        DESFireAccessRights ar;
        ar.readAccess         = AR_KEY2;
        ar.writeAccess        = AR_KEY1;
        ar.readAndWriteAccess = AR_KEY1;
        ar.changeAccess       = AR_KEY1;
        cmdev1->createStdDataFile(0x00, CM_ENCRYPT, ar, 4, 0);*/

    cmd->authenticate(0x00, newkey);
    cmd->changeKey(0x01, key);
    //  LLA_SUBTEST_PASSED("ChangeKey");

    pcsc_test_shutdown(readerUnit);
    return EXIT_SUCCESS;
}
