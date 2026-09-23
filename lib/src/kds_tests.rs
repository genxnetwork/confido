use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serve(responses: Vec<&'static str>) -> (String, tokio::task::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/test", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut count = 0;
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            stream.read(&mut request).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
            count += 1;
        }
        count
    });
    (url, task)
}

#[tokio::test]
async fn retries_429_using_retry_after() {
    let (url, server) = serve(vec![
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ncert",
    ])
    .await;
    let client = Client::new();
    assert_eq!(
        request_with_retry(&client, &url, "test").await.unwrap(),
        b"cert"
    );
    assert_eq!(server.await.unwrap(), 2);
}

#[tokio::test]
async fn does_not_retry_other_client_errors() {
    let (url, server) = serve(vec![
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ])
    .await;
    let client = Client::new();
    let error = request_with_retry(&client, &url, "test").await.unwrap_err();
    assert!(error.to_string().contains("HTTP 404"));
    assert_eq!(server.await.unwrap(), 1);
}

#[tokio::test]
async fn caches_successful_responses() {
    let (url, server) = serve(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ncert",
    ])
    .await;
    let parse = |bytes: &[u8]| -> KdsResult<String> { Ok(String::from_utf8(bytes.to_vec())?) };
    let (first, second) = tokio::join!(
        get_cached(&url, "test", parse),
        get_cached(&url, "test", parse)
    );
    assert_eq!(first.unwrap(), "cert");
    assert_eq!(second.unwrap(), "cert");
    assert_eq!(get_cached(&url, "test", parse).await.unwrap(), "cert");
    assert_eq!(server.await.unwrap(), 1);
}

#[test]
fn parses_retry_after_seconds_and_http_dates() {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, "12".parse().unwrap());
    assert_eq!(retry_after(&headers), Some(Duration::from_secs(12)));
    let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(30));
    headers.insert(RETRY_AFTER, date.parse().unwrap());
    assert!(retry_after(&headers).unwrap() <= Duration::from_secs(30));
    assert!(retry_after(&headers).unwrap() >= Duration::from_secs(28));
}

#[tokio::test]
async fn rejects_oversized_kds_response_without_retry() {
    let (url, server) = serve(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n",
    ])
    .await;
    assert!(request_with_retry(&Client::new(), &url, "test")
        .await
        .unwrap_err()
        .to_string()
        .contains("size limit"));
    assert_eq!(server.await.unwrap(), 1);
}

#[tokio::test]
async fn rejects_retry_after_beyond_total_deadline() {
    let (url,server)=serve(vec!["HTTP/1.1 429 Too Many Requests\r\nRetry-After: 61\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"]).await;
    assert!(request_with_retry(&Client::new(), &url, "test")
        .await
        .unwrap_err()
        .to_string()
        .contains("60-second"));
    assert_eq!(server.await.unwrap(), 1);
}
