use crate::client::error::ClientError;
use anyhow::Result;
use backoff::ExponentialBackoff;
use tokio::net::TcpStream;

/// Tries to execute a future related to a connection to an endpoint.
/// It retries to connect following an exponential policy.
///
/// # Arguments
///
/// * `connection` - Future that represent the connection to the endpoint.
///
/// # Returns
///
/// Returns an error if the connection failed.
pub(crate) async fn test_connection(address: &str) -> Result<(), ClientError> {
    // Try to connect to the proof server
    let res = backoff::future::retry(ExponentialBackoff::default(), || async {
        Ok(TcpStream::connect(address).await?)
    })
    .await;

    if res.is_err() {
        return Err(ClientError::Connection {
            address: address.to_string(),
        });
    }

    Ok(())
}
