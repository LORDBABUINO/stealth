use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use stealth_engine::engine::{AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};
use stealth_engine::Report;

use crate::error::ApiError;
use crate::GatewayState;

pub fn router() -> Router<GatewayState> {
    Router::new().route("/scan", post(scan_post))
}

#[derive(Debug, Deserialize)]
struct ScanRequestBody {
    #[serde(default)]
    descriptor: Option<String>,
    #[serde(default)]
    descriptors: Option<Vec<String>>,
    #[serde(default)]
    utxos: Option<Vec<UtxoInput>>,
}

async fn scan_post(
    State(gateway): State<GatewayState>,
    Json(body): Json<ScanRequestBody>,
) -> Result<Json<Report>, ApiError> {
    let target = body.into_scan_target()?;

    let gw = gateway.ok_or(ApiError::ScannerNotConfigured)?;
    let report = tokio::task::spawn_blocking(move || {
        let engine = AnalysisEngine::new(gw.as_ref(), EngineSettings::default());
        engine.analyze(target)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))??;

    Ok(Json(report))
}

impl ScanRequestBody {
    fn into_scan_target(self) -> Result<ScanTarget, ApiError> {
        match (self.descriptor, self.descriptors, self.utxos) {
            (Some(d), None, None) => Ok(ScanTarget::Descriptor(d)),
            (None, Some(ds), None) => Ok(ScanTarget::Descriptors(ds)),
            (None, None, Some(utxos)) => Ok(ScanTarget::Utxos(utxos)),
            (None, None, None) => Err(ApiError::bad_request(
                "one input source is required: descriptor, descriptors, or utxos",
            )),
            _ => Err(ApiError::bad_request("provide exactly one input source")),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use crate::app;

    #[tokio::test]
    async fn get_scan_is_not_allowed() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn post_scan_requires_one_input_source() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn post_scan_rejects_multiple_sources() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "descriptor": "wpkh(xpub.../0/*)",
                            "utxos": [
                                {
                                    "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                                    "vout": 0
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn post_scan_returns_503_without_rpc_config() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "descriptor": "wpkh(xpub.../0/*)" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "scanner_not_configured");
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
