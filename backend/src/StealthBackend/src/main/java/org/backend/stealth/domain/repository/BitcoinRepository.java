package org.backend.stealth.domain.repository;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.bitcoindevkit.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Repository for Bitcoin blockchain connection (Testnet4)
 */
@ApplicationScoped
public class BitcoinRepository {

    private static final Logger logger = LoggerFactory.getLogger(BitcoinRepository.class);

    private Blockchain blockchain;
    private Wallet wallet;
    private final Network network = Network.TESTNET;
    private final String esploraUrl = "https://mempool.space/testnet4/api";

    @PostConstruct
    public void init() {
        logger.info("🚀 Iniciando conexão com Bitcoin Testnet4...");
        connectBlockchain();
    }

    /**
     * Connect to Bitcoin blockchain
     */
    public void connectBlockchain() {
        try {
            logger.info("📡 Conectando em: {}", esploraUrl);

            // Create Esplora config - using correct Kotlin UByte conversion
            EsploraConfig esploraConfig = new EsploraConfig(
                esploraUrl,
                null,
                kotlin.UByte.valueOf((byte) 5),  // timeout 5 seconds
                (long) 100,
                null
            );

            // Create blockchain config using correct method
            BlockchainConfig blockchainConfig = new BlockchainConfig.Esplora(esploraConfig);

            // Create blockchain
            blockchain = new Blockchain(blockchainConfig);

            logger.info("✅ Blockchain conectado com sucesso!");

            // Get height
            long height = blockchain.height();
            logger.info("📊 Altura da blockchain: {} blocos", height);

            // Initialize wallet
            createWallet();

        } catch (Exception e) {
            logger.error("❌ Erro ao conectar: {}", e.getMessage(), e);
        }
    }

    /**
     * Create a new wallet
     */
    private void createWallet() {
        try {
            logger.info("🔑 Criando wallet...");

            // Generate mnemonic
            Mnemonic mnemonic = new Mnemonic(WordCount.WORDS12);
            logger.warn("⚠️  GUARDE ESTAS PALAVRAS:");
            logger.warn("📝 {}", mnemonic.asString());

            // Create descriptor secret key
            DescriptorSecretKey descriptorSecretKey = new DescriptorSecretKey(
                network,
                mnemonic,
                null
            );

            // Create descriptors (BIP84)
            String descStr = "wpkh(" + descriptorSecretKey.asString() + "/84'/1'/0'/0/*)";
            String changeDescStr = "wpkh(" + descriptorSecretKey.asString() + "/84'/1'/0'/1/*)";

            Descriptor descriptor = new Descriptor(descStr, network);
            Descriptor changeDescriptor = new Descriptor(changeDescStr, network);

            // Create database config
            DatabaseConfig databaseConfig = DatabaseConfig.memory();

            // Create wallet
            wallet = new Wallet(descriptor, changeDescriptor, network, databaseConfig);

            logger.info("✅ Wallet criada!");

            // Sync and show address
            syncWallet();
            showAddress();

        } catch (Exception e) {
            logger.error("❌ Erro ao criar wallet: {}", e.getMessage(), e);
        }
    }

    /**
     * Sync wallet with blockchain
     */
    public void syncWallet() {
        try {
            if (wallet != null && blockchain != null) {
                logger.info("🔄 Sincronizando...");
                wallet.sync(blockchain, null);
                logger.info("✅ Sincronizado!");

                Balance balance = wallet.balance();
                logger.info("💵 Saldo: {} satoshis", balance.total());
            }
        } catch (Exception e) {
            logger.error("❌ Erro ao sincronizar: {}", e.getMessage(), e);
        }
    }

    /**
     * Show a receiving address
     */
    private void showAddress() {
        try {
            AddressInfo addressInfo = wallet.revealNextAddress(KeychainKind.EXTERNAL);
            logger.info("💰 Endereço: {}", addressInfo.address().asString());
            logger.info("📍 Para receber testnet coins: https://mempool.space/testnet4");
        } catch (Exception e) {
            logger.error("Erro ao gerar endereço: {}", e.getMessage(), e);
        }
    }

    /**
     * Get blockchain height
     */
    public long getHeight() {
        return blockchain != null ? blockchain.height() : -1;
    }

    /**
     * Get new address
     */
    public String getNewAddress() {
        try {
            if (wallet == null) return null;
            AddressInfo addressInfo = wallet.revealNextAddress(KeychainKind.EXTERNAL);
            return addressInfo.address().asString();
        } catch (Exception e) {
            logger.error("Erro: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Get balance
     */
    public Balance getBalance() {
        try {
            if (wallet == null) return null;
            syncWallet();
            return wallet.balance();
        } catch (Exception e) {
            logger.error("Erro: {}", e.getMessage());
            return null;
        }
    }

    public boolean isConnected() {
        return blockchain != null;
    }

    public Blockchain getBlockchain() {
        return blockchain;
    }

    public Wallet getWallet() {
        return wallet;
    }

    public Network getNetwork() {
        return network;
    }
}

