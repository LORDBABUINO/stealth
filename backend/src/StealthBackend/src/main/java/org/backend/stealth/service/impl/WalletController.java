package org.backend.stealth.service.impl;

import org.bitcoindevkit.*;

public class WalletController {

    public void ConnectWallet() throws BdkException {

        Mnemonic mnemonic = new Mnemonic(WordCount.WORDS12);

        DescriptorSecretKey masterKey = new DescriptorSecretKey(
                Network.REGTEST,
                mnemonic,
                ""
        );

        String externalDescStr = "wpkh(" + masterKey.asString() + "/84'/1'/0'/0/*)";

        Descriptor externalDescriptor = new Descriptor(externalDescStr, Network.REGTEST);

        Wallet wallet = new Wallet(
                externalDescriptor,
                null, // changeDescriptor (pode continuar null por enquanto)
                Network.REGTEST,
                DatabaseConfig.Memory.INSTANCE
        );

        System.out.println("✅ Carteira criada com sucesso! Endereço: " +
                wallet.getAddress(AddressIndex.New.INSTANCE).getAddress());
    }
}