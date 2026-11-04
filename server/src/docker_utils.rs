use bollard::API_DEFAULT_VERSION;
use bollard::Docker;
use bollard::container::ListContainersOptions;
use futures_util::TryStreamExt;
use serde_json::{json, Value};

/// Retrieves a list of running Docker containers and their corresponding image digests.
pub async fn get_running_containers() -> serde_json::Value {
    let docker = Docker::connect_with_unix("/var/run/docker.sock", 120, bollard::API_DEFAULT_VERSION)
        .expect("Failed to connect to Docker socket");

    let options = ListContainersOptions::<String> {
        all: false,
        ..Default::default()
    };

    match docker.list_containers(Some(options)).await {
        Ok(containers) => {
            let mut results = Vec::new();

            for container in containers {
                let container_id = container.id.unwrap_or_default();
                let image_name = container.image.unwrap_or_default();
                let image_id = container.image_id.unwrap_or_default();

                // Fetch image digest
                let image_inspect = docker.inspect_image(&image_id).await;

                let image_digest = match image_inspect {
                    Ok(image_info) => image_info
                        .repo_digests
                        .unwrap_or_default()
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    Err(_) => "Unknown".into(),
                };

                results.push(json!({
                    "container_id": container_id,
                    "image": image_name,
                    "image_digest": image_digest
                }));
            }
            json!(results)
        }
        Err(e) => json!({"error": format!("Docker API error: {}", e)}),
    }
}

