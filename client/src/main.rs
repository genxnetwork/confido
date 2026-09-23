use confido::appraisal::{self, AppraisalConfig, EvidenceBundle, Status};
use std::{error::Error, path::Path};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    confido::atls::atls_debug();
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("confido_client {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.len() < 4 {
        return Err("Usage: confido_client appraise POLICY.json NEW_BUNDLE.json | replay POLICY.json BUNDLE.json EVALUATION_UNIX_TIME".into());
    }
    let config: AppraisalConfig = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    let result = match args[1].as_str() {
        "appraise" => {
            let preview = appraisal::discover(&config).await?;
            let outcome = appraisal::connect(&config, preview).await;
            if let Some(bundle) = outcome.bundle {
                appraisal::save_private_json(Path::new(&args[3]), &bundle)?;
            }
            appraisal::save_private_json(
                &Path::new(&args[3]).with_extension("result.json"),
                &outcome.result,
            )?;
            outcome.result
        }
        "replay" => {
            if std::fs::metadata(&args[3])?.len() > appraisal::MAX_BUNDLE as u64 {
                return Err("Bundle exceeds size limit".into());
            }
            let bundle: EvidenceBundle = serde_json::from_slice(&std::fs::read(&args[3])?)?;
            let at = args
                .get(4)
                .ok_or("Replay requires an independently chosen evaluation time")?
                .parse()?;
            appraisal::appraise(&bundle, &config, at)
        }
        _ => return Err("Expected appraise or replay".into()),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    if result.status != Status::Passed {
        std::process::exit(2);
    }
    Ok(())
}
