use alloy_signer_local::PrivateKeySigner;
use reqwest::Client;
use x402_4mica::client::Eip155FourMicaClient;
use x402_reqwest::{ReqwestWithPayments, ReqwestWithPaymentsBuild, X402Client};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();

    let private_key = std::env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        eprintln!("Error: PRIVATE_KEY environment variable must be set and start with 0x");
        eprintln!("Example: PRIVATE_KEY=0x1234... cargo run --example client");
        std::process::exit(1);
    });

    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let endpoint = format!("{}/api/premium-data", api_url);

    println!("Initializing x402 client...");
    println!("Target endpoint: {}", endpoint);

    let signer: PrivateKeySigner = private_key
        .parse()
        .expect("Invalid private key format. Must start with 0x");

    println!("Using account: {}", signer.address());

    let x402_client = X402Client::new().register(Eip155FourMicaClient::new(signer));

    let http_client = Client::new().with_payments(x402_client).build();

    println!("\nMaking request to protected endpoint...");

    match http_client.get(&endpoint).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(body) => {
                        println!("Request successful!");
                        println!("Response: {}", body);
                    }
                    Err(e) => {
                        eprintln!("Failed to read response body: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Request failed with status: {}", response.status());
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Request failed: {}", e);
            std::process::exit(1);
        }
    }
}
