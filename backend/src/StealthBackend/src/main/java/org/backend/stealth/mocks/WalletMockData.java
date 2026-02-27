package org.backend.stealth.mocks;

import org.backend.stealth.controller.WalletResource.ReportResponse;
import org.backend.stealth.controller.WalletResource.SummaryData;
import org.backend.stealth.controller.WalletResource.UtxoData;
import org.backend.stealth.controller.WalletResource.VulnerabilityData;

import java.util.List;

public class WalletMockData {

    public static ReportResponse buildReport(String descriptor) {
        List<UtxoData> utxos = List.of(
            new UtxoData(
                "3a7f2b8c1d4e9f0a6b5c2d7e8f3a1b4c9d2e5f0a7b8c1d4e9f2a5b6c3d7e8f1",
                0,
                "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                0.05234891,
                1842,
                List.of()
            ),
            new UtxoData(
                "b4c8e2f6a1d5b9c3e7f1a5d9b3c7e1f5a9d3b7c1e5f9a3d7b1c5e9f3a7d1b5",
                1,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                0.00023000,
                312,
                List.of(
                    new VulnerabilityData("DUST_SPEND", "medium",
                        "This UTXO is near the dust threshold. Spending it may cost more in fees than its value, and dust outputs are often used as tracking vectors by chain surveillance companies."),
                    new VulnerabilityData("ADDRESS_REUSE", "high",
                        "This address has received funds in 3 separate transactions. Address reuse breaks the one-time-address privacy model and allows observers to link all deposits to the same wallet.")
                )
            ),
            new UtxoData(
                "f9e3d7c1b5a9f3d7c1b5a9f3d7c1b5a9f3d7c1b5a9f3d7c1b5a9f3d7c1b5a9",
                0,
                "bc1q9h7garjcdkl4h5khfz2yxkhsmhep5j7g4cjtch",
                0.12000000,
                4521,
                List.of(
                    new VulnerabilityData("CONSOLIDATION", "medium",
                        "This UTXO was created by consolidating 7 inputs in a single transaction. Consolidation reveals that all input addresses belong to the same wallet, reducing privacy significantly.")
                )
            ),
            new UtxoData(
                "2c6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d6e0a4f8b2d",
                2,
                "bc1qm34mqf4vn8f5vhf0q3djg2zuzfm9aap6e3n4j",
                0.87654321,
                98,
                List.of(
                    new VulnerabilityData("CIOH", "high",
                        "Common Input Ownership Heuristic (CIOH): this UTXO was spent alongside UTXOs from different derivation paths in the same transaction, strongly suggesting to analysts that all inputs share a common owner."),
                    new VulnerabilityData("ADDRESS_REUSE", "high",
                        "This address appears in 5 transactions as both sender and receiver, a pattern that severely compromises wallet privacy and makes cluster analysis trivial.")
                )
            ),
            new UtxoData(
                "7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d1b5e9f3a7d",
                0,
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8zeqchgx",
                0.00500000,
                2103,
                List.of(
                    new VulnerabilityData("DUST_SPEND", "low",
                        "A small dust amount was received at this address in a prior transaction. While the dust has not been spent, its presence could be used to track this UTXO if included in a future transaction.")
                )
            )
        );

        SummaryData summary = new SummaryData(5, 1, 4);
        return new ReportResponse(descriptor, summary, utxos);
    }
}
