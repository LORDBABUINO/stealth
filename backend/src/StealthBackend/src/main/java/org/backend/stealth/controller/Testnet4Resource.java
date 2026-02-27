package org.backend.stealth.controller;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.backend.stealth.domain.repository.BitcoinRepository;
import org.backend.stealth.service.dto.*;
import org.bitcoindevkit.Balance;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * REST API para conexão com Bitcoin Testnet4
 */
@Path("/api/testnet4")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Bitcoin Testnet4", description = "Operações com blockchain Bitcoin testnet4")
public class Testnet4Resource {

    @Inject
    BitcoinRepository bitcoinRepository;

    @GET
    @Path("/status")
    @Operation(summary = "Verificar status da conexão", description = "Verifica se está conectado na blockchain testnet4")
    public Response getStatus() {
        try {
            boolean connected = bitcoinRepository.isConnected();
            long height = connected ? bitcoinRepository.getHeight() : -1;

            String status = connected ? "✅ Conectado" : "❌ Desconectado";

            return Response.ok(new Testnet4StatusDTO(
                connected,
                status,
                height,
                "https://mempool.space/testnet4/api"
            )).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorDTO("Erro: " + e.getMessage()))
                .build();
        }
    }

    @GET
    @Path("/height")
    @Operation(summary = "Obter altura da blockchain", description = "Retorna o número atual de blocos")
    public Response getHeight() {
        try {
            long height = bitcoinRepository.getHeight();
            return Response.ok(new BlockHeightDTO(height)).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorDTO("Erro: " + e.getMessage()))
                .build();
        }
    }

    @GET
    @Path("/address")
    @Operation(summary = "Gerar novo endereço", description = "Gera um novo endereço para receber testnet4 bitcoins")
    public Response getNewAddress() {
        try {
            String address = bitcoinRepository.getNewAddress();

            if (address == null) {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorDTO("Erro ao gerar endereço"))
                    .build();
            }

            return Response.ok(new AddressResponseDTO(
                address,
                "Use um faucet para receber testnet4 bitcoins: https://mempool.space/testnet4"
            )).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorDTO("Erro: " + e.getMessage()))
                .build();
        }
    }

    @GET
    @Path("/balance")
    @Operation(summary = "Verificar saldo", description = "Retorna o saldo da wallet")
    public Response getBalance() {
        try {
            Balance balance = bitcoinRepository.getBalance();

            if (balance == null) {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorDTO("Erro ao obter saldo"))
                    .build();
            }

            return Response.ok(new BalanceDTO(
                balance.total(),
                balance.confirmed(),
                balance.immature(),
                balance.trustedPending(),
                balance.untrustedPending()
            )).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorDTO("Erro: " + e.getMessage()))
                .build();
        }
    }

    @POST
    @Path("/sync")
    @Operation(summary = "Sincronizar wallet", description = "Sincroniza a wallet com a blockchain")
    public Response sync() {
        try {
            bitcoinRepository.syncWallet();
            return Response.ok(new MessageDTO("✅ Wallet sincronizada com sucesso!")).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorDTO("Erro: " + e.getMessage()))
                .build();
        }
    }
}

