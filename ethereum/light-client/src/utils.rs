use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Auxiliary function to write bytes on a stream. Before actually writing the
/// bytes, it writes the number of bytes to be written as a big-endian `u32`.
///
/// # Errors
/// This function errors if the number of bytes can't fit in a `u32`
pub async fn write_bytes(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    stream.write_u32(u32::try_from(bytes.len())?).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Auxiliary function to read bytes on a stream. Before actually reading the
/// bytes, it reads the number of bytes to be read as a big-endian `u32`.
///
/// # Important
/// The number of bytes read must fit in a `u32` thus the amount of data read in
/// a single call to this function is 4 GB.
pub async fn read_bytes(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let size = stream.read_u32().await?;
    let mut bytes = vec![0; size as usize];
    let num_read = stream.read_exact(&mut bytes).await?;
    assert_eq!(num_read, bytes.len());
    Ok(bytes)
}
