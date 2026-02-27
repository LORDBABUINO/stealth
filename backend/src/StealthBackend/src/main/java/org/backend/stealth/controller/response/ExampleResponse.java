package org.backend.stealth.controller.response;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.backend.stealth.service.impl.WalletController;
import org.bitcoindevkit.BdkException;

@Path("/hello")
public class ExampleResponse {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() throws BdkException {

        WalletController controller = new WalletController();
        controller.ConnectWallet();

        return "Hello from Quarkus REST";
    }
}
