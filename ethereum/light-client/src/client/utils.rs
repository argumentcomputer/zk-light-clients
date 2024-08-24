use crate::client::error::ClientError;
use anyhow::Result;
use backoff::ExponentialBackoff;
use std::future::Future;

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
pub(crate) async fn test_connection(connection: impl Future) -> Result<(), ClientError> {
    // Try to connect to the proof server
    let res = backoff::future::retry(ExponentialBackoff::default(), connection).await;

    if res.is_err() {
        return Err(ClientError::Connection {
            address: self.beacon_node_address.clone(),
        });
    }

    Ok(())
}
