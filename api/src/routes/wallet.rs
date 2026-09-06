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
    #[serde(default)]
    rescan_since: Option<u64>,
}

async fn scan_post(
    State(gateway): State<GatewayState>,
    Json(body): Json<ScanRequestBody>,
) -> Result<Json<Report>, ApiError> {
    let rescan_since = body.rescan_since;
    let (target, ownership_descriptors) = body.into_scan_request()?;

    let gw = gateway.ok_or(ApiError::ScannerNotConfigured)?;
    let report = tokio::task::spawn_blocking(move || {
        let settings = EngineSettings {
            rescan_since,
            ownership_descriptors,
            ..EngineSettings::default()
        };
        let engine = AnalysisEngine::new(gw.as_ref(), settings);
        engine.analyze(target)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))??;

    Ok(Json(report))
}

impl ScanRequestBody {
    fn into_scan_request(self) -> Result<(ScanTarget, Vec<String>), ApiError> {
        match (self.descriptor, self.descriptors, self.utxos) {
            (Some(d), None, None) => Ok((ScanTarget::Descriptor(d), Vec::new())),
            (None, Some(ds), None) if !ds.is_empty() => {
                Ok((ScanTarget::Descriptors(ds), Vec::new()))
            }
            (None, Some(_), None) => Err(ApiError::bad_request("`descriptors` must not be empty")),
            (None, None, Some(utxos)) if !utxos.is_empty() => {
                Ok((ScanTarget::Utxos(utxos), Vec::new()))
            }
            (None, None, Some(_)) => Err(ApiError::bad_request("`utxos` must not be empty")),
            // utxos + descriptors: the descriptors are ownership context,
            // letting is_ours() recognise the user's own inputs.
            (None, Some(ds), Some(utxos)) if !utxos.is_empty() && !ds.is_empty() => {
                Ok((ScanTarget::Utxos(utxos), ds))
            }
            (None, Some(_), Some(_)) => Err(ApiError::bad_request(
                "`utxos` and `descriptors` must not be empty when combined",
            )),
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
    async fn post_scan_rejects_empty_descriptors_list() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "descriptors": [] }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn post_scan_rejects_empty_utxos_list() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/wallet/scan")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "utxos": [] }).to_string()))
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
