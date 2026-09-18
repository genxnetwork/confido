// example client showcasing the usage of the ATLS library
#[warn(unused_variables)]

use confido::atls::ATLS;
use tokio;
use std::env;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let args: Vec<String> = env::args().collect();
    let server_url = if args.len() > 1 {
        args[1].clone()
    } else {
        "http://127.0.0.1:8000".to_string()
    };
    
    println!("Connecting to server: {}", server_url);
    
    let atls = ATLS::connect(&server_url).await.map_err(|e| {
        log::error!("Failed establish aTLS: {}", e);
        e
    })?;
    
    println!("✓ aTLS connection established successfully!");

    // let response = atls.get("https://localhost/hello").await.map_err(|e| {
    //     log::error!("Failed to request: {}", e);
    //     e
    // })?;
    // log::info!("Response content: {:?}", response);
    
    Ok(())
}