package org.backend.stealth.controller;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.backend.stealth.mocks.WalletMockData;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Path("/api/wallet")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class WalletResource {

    private static final Map<String, String> sessions = new ConcurrentHashMap<>();

    // DTOs

    public record AnalyzeRequest(String descriptor) {}

    public record AnalyzeResponse(String analysisId) {}

    public record VulnerabilityData(String type, String severity, String description) {}

    public record UtxoData(
        String txid,
        int vout,
        String address,
        double amountBtc,
        int confirmations,
        List<VulnerabilityData> vulnerabilities
    ) {}

    public record SummaryData(int total, int clean, int vulnerable) {}

    public record ReportResponse(String descriptor, SummaryData summary, List<UtxoData> utxos) {}

    // Endpoints

    @POST
    @Path("/analyze")
    public Response analyze(AnalyzeRequest req) {
        if (req == null || req.descriptor() == null || req.descriptor().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("error", "descriptor is required"))
                .build();
        }
        String analysisId = UUID.randomUUID().toString();
        sessions.put(analysisId, req.descriptor());
        return Response.ok(new AnalyzeResponse(analysisId)).build();
    }

    @GET
    @Path("/{analysisId}/utxos")
    public Response getUtxos(@PathParam("analysisId") String analysisId) {
        String descriptor = sessions.get(analysisId);
        if (descriptor == null) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("error", "analysisId not found"))
                .build();
        }
        return Response.ok(WalletMockData.buildReport(descriptor)).build();
    }
}
