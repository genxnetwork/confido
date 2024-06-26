// example client showcasing the usage of the ATLS library

use confido::ATLS;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // env_logger::init();
    let atls = ATLS::connect("http://127.0.0.1:8000").await.map_err(|e| {
        log::error!("Failed to connect: {}", e);
        e
    })?;

    let response = atls.get("https://localhost/hello").await.map_err(|e| {
        log::error!("Failed to request: {}", e);
        e
    })?;
    log::info!("Response content: {:?}", response);
    
    Ok(())
}