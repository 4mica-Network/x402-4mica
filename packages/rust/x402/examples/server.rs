use alloy_primitives::Address;
use axum::{Router, routing::get};
use http::StatusCode;
use x402_4mica::{
    SupportedNetworkEip155,
    server::axum::{BuildTabMiddleware, V1Eip155FourMica},
};
use x402_axum::X402Middleware;
use x402_types::networks::USDC;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid number");

    let pay_to_address: Address = std::env::var("PAY_TO_ADDRESS")
        .unwrap_or_else(|_| {
            eprintln!("Error: PAY_TO_ADDRESS environment variable must be set and start with 0x");
            eprintln!("Example: PAY_TO_ADDRESS=0x1234... cargo run --example server");
            std::process::exit(1);
        })
        .parse()
        .expect("PAY_TO_ADDRESS must be a valid Ethereum address");

    let x402 = X402Middleware::new("https://x402.4mica.xyz");

    let tab_middleware = x402
        .tab_middleware()
        .expect("Failed to build tab middleware");

    let app = Router::new()
        .route(
            "/api/premium-data",
            get(premium_handler).layer(x402.with_price_tag(V1Eip155FourMica::price_tag(
                pay_to_address,
                USDC::ethereum_sepolia().parse("0.01").unwrap(),
            ))),
        )
        .route("/", get(root_handler))
        .layer(tab_middleware);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    println!("x402 Demo Server running on http://localhost:{}", port);
    println!(
        "Protected endpoint: http://localhost:{}/api/premium-data",
        port
    );
    println!("Payment required: $0.01 (4mica credit on Sepolia)");

    axum::serve(listener, app).await.unwrap();
}

async fn premium_handler() -> (StatusCode, String) {
    let response = serde_json::json!({
        "message": "Success! You've accessed the premium data.",
        "data": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "secret": "This is protected content behind a paywall",
            "value": rand::random::<f64>() * 1000.0,
        }
    });

    (
        StatusCode::OK,
        serde_json::to_string_pretty(&response).unwrap(),
    )
}

async fn root_handler() -> (StatusCode, String) {
    let response = serde_json::json!({
        "message": "x402 Demo Server",
        "endpoints": {
            "free": ["/", "/health"],
            "protected": [{
                "path": "/api/premium-data",
                "price": "$0.01",
                "description": "Premium data endpoint (requires payment)"
            }]
        }
    });

    (
        StatusCode::OK,
        serde_json::to_string_pretty(&response).unwrap(),
    )
}
