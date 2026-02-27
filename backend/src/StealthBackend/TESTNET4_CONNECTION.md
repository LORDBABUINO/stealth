# Conexão com Bitcoin Testnet4

Este guia mostra como conectar na blockchain Bitcoin testnet4 usando BDK-JVM.

## 🚀 Como Funciona

### 1. Executar o Exemplo de Conexão

#### Opção A: Via Código Java
Execute a classe `BitcoinConnectionExample`:

```bash
cd /home/herbe/src/stealth/backend/src/StealthBackend
mvn compile
mvn exec:java -Dexec.mainClass="org.backend.stealth.service.BitcoinConnectionExample"
```

#### Opção B: Via REST API
Inicie o servidor Quarkus:

```bash
./mvnw quarkus:dev
```

Acesse os endpoints:

**1. Conectar na blockchain testnet4:**
```bash
curl -X POST http://localhost:8080/api/testnet4/connect
```

**2. Obter informações da blockchain:**
```bash
curl http://localhost:8080/api/testnet4/info
```

**3. Gerar novo endereço:**
```bash
curl http://localhost:8080/api/testnet4/address
```

**4. Verificar saldo:**
```bash
curl http://localhost:8080/api/testnet4/balance
```

**5. Sincronizar wallet:**
```bash
curl -X POST http://localhost:8080/api/testnet4/sync
```

## 📊 O Que o Código Faz

### 1. Configuração da Network
```java
Network network = Network.TESTNET;
```
Define que vamos usar a testnet do Bitcoin.

### 2. Configuração do Esplora
```java
String esploraUrl = "https://mempool.space/testnet4/api";
EsploraConfig esploraConfig = new EsploraConfig(
    esploraUrl,     // URL do servidor Esplora
    null,           // Proxy (null = sem proxy)
    5L,             // Timeout em segundos
    null,           // Stop gap
    null            // Timeout para requests longos
);
```
Esplora é uma API que permite acessar dados da blockchain sem rodar um nó completo.

### 3. Conexão com Blockchain
```java
BlockchainConfig blockchainConfig = BlockchainConfig.esplora(esploraConfig);
Blockchain blockchain = new Blockchain(blockchainConfig);
```
Cria a conexão com a blockchain testnet4.

### 4. Verificar Conexão
```java
long height = blockchain.getHeight();
String blockHash = blockchain.getBlockHash(height);
```
Obtém a altura atual (número de blocos) e o hash do último bloco.

### 5. Criar Wallet
```java
Mnemonic mnemonic = new Mnemonic(WordCount.WORDS12);
DescriptorSecretKey descriptorSecretKey = new DescriptorSecretKey(network, mnemonic, null);

String descriptor = "wpkh(" + descriptorSecretKey.asString() + "/84'/1'/0'/0/*)";
String changeDescriptor = "wpkh(" + descriptorSecretKey.asString() + "/84'/1'/0'/1/*)";

Wallet wallet = new Wallet(descriptor, changeDescriptor, network, databaseConfig);
```
Cria uma wallet HD (Hierarchical Deterministic) usando BIP84 (native segwit).

### 6. Sincronizar Wallet
```java
wallet.sync(blockchain, null);
```
Sincroniza a wallet com a blockchain para obter transações e saldo.

### 7. Gerar Endereço
```java
AddressInfo addressInfo = wallet.getAddress(AddressIndex.NEW);
```
Gera um novo endereço para receber bitcoins.

## 🔑 Componentes Principais

### Blockchain
- Representa a conexão com a rede Bitcoin
- Permite consultar blocos, altura, e broadcast de transações

### Wallet
- Gerencia chaves privadas e endereços
- Rastreia saldo e transações
- Cria e assina transações

### Mnemonic
- 12 palavras que permitem recuperar a wallet
- **MUITO IMPORTANTE**: Guarde com segurança!
- Qualquer pessoa com essas palavras tem acesso aos fundos

### Descriptor
- Define a estrutura da wallet
- `wpkh` = Witness Public Key Hash (native segwit)
- `/84'/1'/0'/0/*` = Caminho BIP84 para testnet

## 💰 Como Obter Testnet4 Bitcoins

1. Execute o código para gerar um endereço
2. Copie o endereço gerado (começa com `tb1...`)
3. Acesse um faucet de testnet4:
   - https://mempool.space/testnet4
   - Procure por "faucet" na página
4. Cole seu endereço e solicite bitcoins
5. Aguarde alguns minutos para confirmação
6. Sincronize a wallet e verifique o saldo

## 🔧 Estrutura do Código

```
src/main/java/org/backend/stealth/
├── service/
│   ├── BitcoinController.java          # Controller principal com lógica de conexão
│   └── BitcoinConnectionExample.java   # Exemplo standalone
├── controller/
│   └── BitcoinTestnet4Resource.java    # REST API endpoints
└── service/dto/
    ├── BlockchainInfoDTO.java          # DTO para info da blockchain
    ├── AddressResponseDTO.java         # DTO para endereços
    ├── BalanceDTO.java                 # DTO para saldo
    ├── ErrorDTO.java                   # DTO para erros
    └── MessageDTO.java                 # DTO para mensagens
```

## 📝 Exemplo de Resposta

### GET /api/testnet4/info
```json
{
  "network": "TESTNET4",
  "height": 150234,
  "latestBlockHash": "00000000000000123abc...",
  "esploraUrl": "https://mempool.space/testnet4/api"
}
```

### GET /api/testnet4/address
```json
{
  "address": "tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
  "instructions": "Use um faucet para receber testnet4 bitcoins: https://mempool.space/testnet4"
}
```

### GET /api/testnet4/balance
```json
{
  "total": 100000,
  "confirmed": 100000,
  "immature": 0,
  "trustedPending": 0,
  "untrustedPending": 0
}
```

## ⚠️ Notas Importantes

1. **Testnet4**: Esta é uma rede de testes. Os bitcoins não têm valor real.
2. **Mnemonic**: Sempre guarde as 12 palavras em local seguro.
3. **Esplora**: Dependemos de um servidor externo. Se estiver lento, pode ser problema na API.
4. **Sincronização**: A primeira sincronização pode demorar alguns segundos.

## 🐛 Troubleshooting

### Erro: "Connection timeout"
- Verifique sua conexão com internet
- Tente usar outro servidor Esplora
- Aumente o timeout na configuração

### Erro: "Invalid descriptor"
- Verifique se está usando Network.TESTNET
- Confirme que o descriptor está correto

### Saldo sempre zero
- Aguarde a confirmação da transação (10-60 minutos)
- Sincronize a wallet novamente
- Verifique se usou o endereço correto no faucet

## 📚 Recursos Adicionais

- [BDK Documentation](https://bitcoindevkit.org/)
- [Mempool.space Testnet4](https://mempool.space/testnet4)
- [BIP84 Specification](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- [Bitcoin Testnet Guide](https://developer.bitcoin.org/examples/testing.html)

## ✅ Checklist de Teste

- [ ] Executar `BitcoinConnectionExample`
- [ ] Ver log de conexão bem-sucedida
- [ ] Verificar altura da blockchain
- [ ] Salvar as 12 palavras do mnemonic
- [ ] Copiar endereço gerado
- [ ] Solicitar bitcoins no faucet
- [ ] Sincronizar wallet
- [ ] Verificar saldo atualizado

