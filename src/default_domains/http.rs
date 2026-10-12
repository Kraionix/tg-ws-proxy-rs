use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::log::schema::ErrorCode;
use crate::outbound::{OutboundConnector, OutboundError};

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Why the fetch failed, in the vocabulary a record can carry.
///
/// The class is kept apart from the message on purpose: a record must not read
/// a transport failure back out of its own prose, and "GitHub was unreachable"
/// is a different fact from "the list came back empty".
#[derive(Debug)]
pub struct FetchError {
    pub err: ErrorCode,
    /// The HTTP status when that is what failed, zero otherwise.
    pub err_code: u32,
    /// What the console line used to say, for the caller that prints it.
    pub reason: String,
}

impl FetchError {
    pub fn connect(error: &OutboundError) -> Self {
        Self {
            err: if error.timed_out {
                ErrorCode::TcpConnectTimeout
            } else {
                ErrorCode::TcpConnect
            },
            err_code: 0,
            reason: error.reason.clone(),
        }
    }

    pub fn http(status: u16) -> Self {
        Self {
            err: ErrorCode::HttpStatus,
            err_code: u32::from(status),
            reason: format!("HTTP status {status}"),
        }
    }

    /// The default class for everything else: the response was not the one the
    /// protocol calls for, whether it was cut short, malformed, or not UTF-8.
    pub fn protocol(reason: impl Into<String>) -> Self {
        Self {
            err: ErrorCode::Protocol,
            err_code: 0,
            reason: reason.into(),
        }
    }

    pub fn tls(reason: impl Into<String>) -> Self {
        Self {
            err: ErrorCode::Tls,
            err_code: 0,
            reason: reason.into(),
        }
    }

    pub fn tls_timeout() -> Self {
        Self {
            err: ErrorCode::TlsTimeout,
            err_code: 0,
            reason: "TLS handshake timed out".to_string(),
        }
    }

    pub fn dns(reason: impl Into<String>) -> Self {
        Self {
            err: ErrorCode::Dns,
            err_code: 0,
            reason: reason.into(),
        }
    }

    pub fn read(reason: impl Into<String>) -> Self {
        Self {
            err: ErrorCode::Read,
            err_code: 0,
            reason: reason.into(),
        }
    }
}

/// Build a `rustls` `ClientConfig` using the bundled WebPKI root store.
fn build_tls_config() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Perform an HTTPS GET and return the response body as a `String`.
pub(super) async fn https_get(
    host: &str,
    path: &str,
    outbound: &OutboundConnector,
) -> Result<String, FetchError> {
    https_get_with_tls_config(host, path, outbound, Arc::new(build_tls_config())).await
}

async fn https_get_with_tls_config(
    host: &str,
    path: &str,
    outbound: &OutboundConnector,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<String, FetchError> {
    let connector = TlsConnector::from(tls_config);

    let tcp = outbound
        .connect(host, 443, FETCH_TIMEOUT)
        .await
        .map_err(|e| FetchError::connect(&e))?;
    let _ = tcp.set_nodelay(true);

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| FetchError::dns(format!("invalid server name: {e}")))?;
    let mut tls = tokio::time::timeout(FETCH_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| FetchError::tls_timeout())?
        .map_err(|e| FetchError::tls(format!("TLS handshake: {e}")))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: tg-ws-proxy\r\n\r\n",
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| FetchError::read(format!("write: {e}")))?;

    tokio::time::timeout(FETCH_TIMEOUT, read_http_response_body(&mut tls))
        .await
        .map_err(|_| FetchError::read("read timed out"))?
}

async fn read_http_response_body<R>(reader: &mut R) -> Result<String, FetchError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let header_len = read_until_headers(reader, &mut buf)
        .await
        .map_err(FetchError::read)?;

    let header_count = http_header_count(&buf[..header_len]);
    let mut headers = vec![httparse::EMPTY_HEADER; header_count];
    let mut response = httparse::Response::new(&mut headers);
    match response
        .parse(&buf[..header_len])
        .map_err(|e| FetchError::protocol(format!("HTTP parse error: {e}")))?
    {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => {
            return Err(FetchError::protocol("incomplete HTTP response headers"));
        }
    };

    let code = response
        .code
        .ok_or_else(|| FetchError::protocol("response status line has no status code"))?;
    if code != 200 {
        return Err(FetchError::http(code));
    }

    let declared_len = content_length(response.headers).map_err(FetchError::protocol)?;
    let body = if is_chunked(response.headers) {
        read_chunked_body(reader, buf[header_len..].to_vec())
            .await
            .map_err(FetchError::read)?
    } else if let Some(len) = declared_len {
        read_content_length_body(reader, buf[header_len..].to_vec(), len)
            .await
            .map_err(FetchError::read)?
    } else {
        read_until_eof_limited(reader, buf[header_len..].to_vec())
            .await
            .map_err(FetchError::read)?
    };

    String::from_utf8(body).map_err(|_| FetchError::protocol("response body is not valid UTF-8"))
}

async fn read_until_headers<R>(reader: &mut R, buf: &mut Vec<u8>) -> Result<usize, String>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(pos) = header_end(buf) {
            return Ok(pos);
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err("HTTP response headers exceed limit".to_string());
        }
        read_more(reader, buf, MAX_HEADER_BYTES).await?;
    }
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn http_header_count(headers: &[u8]) -> usize {
    headers.windows(2).filter(|w| *w == b"\r\n").count()
}

fn is_chunked(headers: &[httparse::Header<'_>]) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .filter_map(|header| std::str::from_utf8(header.value).ok())
        .any(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
}

fn content_length(headers: &[httparse::Header<'_>]) -> Result<Option<usize>, String> {
    let mut length = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| "Content-Length is not valid UTF-8".to_string())?
            .trim()
            .parse::<usize>()
            .map_err(|_| "invalid Content-Length".to_string())?;
        if let Some(previous) = length
            && previous != value
        {
            return Err("conflicting Content-Length headers".to_string());
        }
        length = Some(value);
    }
    Ok(length)
}

async fn read_content_length_body<R>(
    reader: &mut R,
    mut body: Vec<u8>,
    len: usize,
) -> Result<Vec<u8>, String>
where
    R: AsyncRead + Unpin,
{
    if len > MAX_BODY_BYTES {
        return Err("HTTP response body exceeds limit".to_string());
    }
    while body.len() < len {
        read_more(reader, &mut body, len).await?;
    }
    body.truncate(len);
    Ok(body)
}

async fn read_chunked_body<R>(reader: &mut R, mut body: Vec<u8>) -> Result<Vec<u8>, String>
where
    R: AsyncRead + Unpin,
{
    let mut decoded = Vec::new();
    let mut pos = 0;

    loop {
        let line_end = loop {
            if let Some(rel) = body[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + rel;
            }
            read_more(reader, &mut body, MAX_BODY_BYTES).await?;
        };

        let size_line = std::str::from_utf8(&body[pos..line_end])
            .map_err(|_| "chunk size is not valid UTF-8".to_string())?;
        let size_hex = size_line
            .split_once(';')
            .map_or(size_line, |(size, _)| size)
            .trim();
        let size =
            usize::from_str_radix(size_hex, 16).map_err(|_| "invalid chunk size".to_string())?;
        pos = line_end + 2;

        if size == 0 {
            read_chunk_trailers(reader, &mut body, pos).await?;
            return Ok(decoded);
        }
        if decoded.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err("HTTP response body exceeds limit".to_string());
        }
        while body.len() < pos + size + 2 {
            read_more(reader, &mut body, MAX_BODY_BYTES).await?;
        }
        decoded.extend_from_slice(&body[pos..pos + size]);
        if &body[pos + size..pos + size + 2] != b"\r\n" {
            return Err("chunk is missing trailing CRLF".to_string());
        }
        pos += size + 2;
    }
}

async fn read_chunk_trailers<R>(
    reader: &mut R,
    body: &mut Vec<u8>,
    mut pos: usize,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    let trailer_start = pos;
    loop {
        let line_end = loop {
            if let Some(rel) = body[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + rel;
            }
            if body.len().saturating_sub(trailer_start) >= MAX_HEADER_BYTES {
                return Err("chunk trailers exceed limit".to_string());
            }
            read_more(reader, body, MAX_BODY_BYTES).await?;
        };

        if line_end == pos {
            return Ok(());
        }
        pos = line_end + 2;
    }
}

async fn read_until_eof_limited<R>(reader: &mut R, mut body: Vec<u8>) -> Result<Vec<u8>, String>
where
    R: AsyncRead + Unpin,
{
    loop {
        if body.len() > MAX_BODY_BYTES {
            return Err("HTTP response body exceeds limit".to_string());
        }
        let remaining = MAX_BODY_BYTES.saturating_sub(body.len());
        let mut chunk = vec![0; remaining.clamp(1, 8192)];
        let n = reader
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Ok(body);
        }
        if body.len().saturating_add(n) > MAX_BODY_BYTES {
            return Err("HTTP response body exceeds limit".to_string());
        }
        body.extend_from_slice(&chunk[..n]);
    }
}

async fn read_more<R>(reader: &mut R, buf: &mut Vec<u8>, limit: usize) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    if buf.len() >= limit {
        return Err("HTTP response exceeds limit".to_string());
    }
    let mut chunk = vec![0; (limit - buf.len()).min(8192)];
    let n = reader
        .read(&mut chunk)
        .await
        .map_err(|e| format!("read: {e}"))?;
    if n == 0 {
        return Err("unexpected EOF while reading HTTP response".to_string());
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

#[cfg(test)]
mod tests;
