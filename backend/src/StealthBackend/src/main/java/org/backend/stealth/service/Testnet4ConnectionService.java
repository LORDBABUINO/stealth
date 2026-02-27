package org.backend.stealth.service;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.bitcoindevkit.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for connecting to Bitcoin Testnet4 blockchain
 * This is a simplified version that connects to testnet4
 */
@ApplicationScoped
public class Testnet4ConnectionService {

    private static final Logger logger = LoggerFactory.getLogger(Testnet4ConnectionService.class);

    private Blockchain blockchain;
    private Wallet wallet;
    private Network network = Network.TESTNET;
    private String esploraUrl = "https://mempool.space/testnet4/api";

    /**
     * Initialize connection on startup
     */
    @PostConstruct
    public void init() {
        logger.info("🚀 Iniciando conexão com Bitcoin Testnet4...");
        connectToBlockchain();
    }

    /**
     * Connect to Bitcoin testnet4 blockchain
     */
    public boolean connectToBlockchain() {
        try {
            logger.info("📡 Configurando conexão Esplora: {}", esploraUrl);

            // Create Esplora configuration
            EsploraConfig esploraConfig = new EsploraConfig(
                esploraUrl,
                null,        // proxy
                (byte) 5,    // timeout in seconds
                (long) 100,  // stop_gap
                null         // timeout for long requests
            );

            // Create blockchain config
            BlockchainConfig blockchainConfig = BlockchainConfig.newEsploraConfig(esploraConfig);

            // Initialize blockchain connection
            blockchain = new Blockchain(blockchainConfig);

            logger.info("✅ Blockchain conectado com sucesso!");

            // Get blockchain info
            long height = blockchain.getHeight();
            logger.info("📊 Altura atual da blockchain: {} blocos", height);

            // Initialize a simple wallet
            initializeWallet();

            return true;

        } catch (Exception e) {
            logger.error("❌ Erro ao conectar na blockchain: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Initialize a simple wallet
     */
    private void initializeWallet() {
        try {
            logger.info("🔑 Inicializando wallet...");

            // Generate mnemonic
            Mnemonic mnemonic = new Mnemonic(WordCount.WORDS12);
            String mnemonicWords = mnemonic.asString();
            logger.warn("⚠️  IMPORTANTE - Guarde essas palavras com segurança:");
            logger.warn("📝 {}", mnemonicWords);

            // Create descriptor secret key
            DescriptorSecretKey descriptorSecretKey = new DescriptorSecretKey(
                network,
                mnemonic,
                null  // no password
            );

            // Create descriptors (BIP84 - native segwit)
            String descriptorStr = "wpkh(" + descriptorSecretKey.asString() + "/84'/1'/0'/0/*)";
            String changeDescriptorStr = "wpkh(" + descriptorSecretKey.asString() + "/84'/1'/0'/1/*)";

            // Create descriptor objects
            Descriptor descriptor = new Descriptor(descriptorStr, network);
            Descriptor changeDescriptor = new Descriptor(changeDescriptorStr, network);

            // Create database config
            DatabaseConfig databaseConfig = new DatabaseConfig.Memory();

            // Create wallet
            wallet = new Wallet(
                descriptor,
                changeDescriptor,
                network,
                databaseConfig
            );

            logger.info("✅ Wallet criada com sucesso!");

            // Sync wallet
            syncWallet();

            // Generate and show address
            AddressInfo addressInfo = wallet.getAddress(new AddressIndex.New());
            logger.info("💰 Endereço para receber: {}", addressInfo.getAddress());
            logger.info("📍 Índice: {}", addressInfo.getIndex());

        } catch (Exception e) {
            logger.error("❌ Erro ao criar wallet: {}", e.getMessage(), e);
        }
    }

    /**
     * Synchronize wallet with blockchain
     */
    public void syncWallet() {
        try {
            if (wallet == null || blockchain == null) {
                logger.error("Wallet ou blockchain não inicializados");
                return;
            }

            logger.info("🔄 Sincronizando wallet...");
            wallet.sync(blockchain, null);
            logger.info("✅ Sincronização completa!");

            // Show balance
            Balance balance = wallet.getBalance();
            logger.info("💵 Saldo total: {} satoshis", balance.getTotal());
            logger.info("💵 Saldo confirmado: {} satoshis", balance.getConfirmed());

        } catch (Exception e) {
            logger.error("❌ Erro ao sincronizar: {}", e.getMessage(), e);
        }
    }

    /**
     * Get blockchain height
     */
    public long getBlockchainHeight() {
        try {
            if (blockchain == null) {
                throw new IllegalStateException("Blockchain não conectado");
            }
            return blockchain.getHeight();
        } catch (Exception e) {
            logger.error("Erro ao obter altura: {}", e.getMessage());
            return -1;
        }
    }

    /**
     * Get new receiving address
     */
    public String getNewAddress() {
        try {
            if (wallet == null) {
                throw new IllegalStateException("Wallet não inicializada");
            }
            AddressInfo addressInfo = wallet.getAddress(new AddressIndex.New());
            return addressInfo.getAddress();
        } catch (Exception e) {
            logger.error("Erro ao gerar endereço: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Get wallet balance
     */
    public Balance getBalance() {
        try {
            if (wallet == null) {
                throw new IllegalStateException("Wallet não inicializada");
            }
            syncWallet();
            return wallet.getBalance();
        } catch (Exception e) {
            logger.error("Erro ao obter saldo: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Check if connected
     */
    public boolean isConnected() {
        return blockchain != null;
    }

    /**
     * Get blockchain instance
     */
    public Blockchain getBlockchain() {
        return blockchain;
    }

    /**
     * Get wallet instance
     */
    public Wallet getWallet() {
        return wallet;
    }

    /**
     * Get network
     */
    public Network getNetwork() {
        return network;
    }

    /**
     * Get Esplora URL
     */
    public String getEsploraUrl() {
        return esploraUrl;
    }
}

