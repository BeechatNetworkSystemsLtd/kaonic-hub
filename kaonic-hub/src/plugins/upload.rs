//! Package uploads: a `multipart/form-data` body read as it arrives, its `file` part written
//! to a private file under `<state>/uploads/` (at most [`MAX_PACKAGE`]), never held whole in
//! memory. The file goes when the [`Package`] is dropped.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::MAX_PACKAGE;
use crate::error::{ApiError, ApiResult};

/// The whole body: the package and the small fields around it.
const MAX_BODY: u64 = MAX_PACKAGE as u64 + 64 * 1024;
/// A field other than the file (the password, `allow_downgrade`).
const MAX_FIELD: usize = 1024;
/// A part's headers.
const MAX_PART_HEAD: usize = 4096;

/// An uploaded package, in its file.
pub struct Package {
    path: PathBuf,
    len: u64,
    sha256: String,
}

impl Package {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// SHA-256 of the package, hex.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl Drop for Package {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Default)]
pub struct Form {
    pub file: Option<Package>,
    pub password: Option<String>,
    pub allow_downgrade: bool,
}

fn bad() -> ApiError {
    ApiError::bad_request("Send the package as multipart/form-data with a file field.")
}

fn too_large() -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "The package is too large.")
}

fn uploads(state_dir: &Path) -> PathBuf {
    state_dir.join("uploads")
}

/// Removes what an earlier run left in the uploads directory.
pub fn clear(state_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(uploads(state_dir)) else { return };
    for entry in entries.flatten() {
        let _ = std::fs::remove_file(entry.path());
    }
}

/// A new private file for an upload.
fn create(state_dir: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let dir = uploads(state_dir);
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let path = dir.join(format!("{}.tar", crate::random::hex(&crate::random::bytes::<16>()?)));
    let file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&path)?;
    Ok((path, file))
}

/// Reads a form with the fields `file`, `password` and `allow_downgrade`; anything else is
/// ignored.
pub async fn read(state_dir: &Path, headers: &HeaderMap, mut body: Body) -> ApiResult<Form> {
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).ok_or_else(bad)?;
    let mut parser = Parser::new(boundary(content_type).ok_or_else(bad)?);
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|length| length > MAX_BODY)
    {
        return Err(too_large());
    }
    let mut form = Form::default();
    let mut file: Option<(tokio::fs::File, PathBuf, Sha256, u64)> = None;
    let mut fields = Fields::default();
    let mut read = 0u64;
    let failed = |path: Option<PathBuf>, error: ApiError| {
        if let Some(path) = path {
            let _ = std::fs::remove_file(path);
        }
        Err(error)
    };
    loop {
        let frame = std::future::poll_fn(|cx| http_body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)).await;
        let Some(frame) = frame else { break };
        let path = file.as_ref().map(|(_, path, _, _)| path.clone());
        let Ok(frame) = frame else { return failed(path, bad()) };
        let Ok(data) = frame.into_data() else { continue };
        read += data.len() as u64;
        if read > MAX_BODY {
            return failed(path, too_large());
        }
        let mut chunk = Vec::new();
        if let Err(error) = parser.feed(&data, &mut |field, bytes| fields.take(field, bytes, &mut chunk)) {
            return failed(path, error);
        }
        if fields.files > 0 && file.is_none() {
            match create(state_dir) {
                Ok((path, std)) => file = Some((tokio::fs::File::from_std(std), path, Sha256::new(), 0)),
                Err(error) => {
                    log::error!("plugins: cannot store an upload: {error}");
                    return Err(ApiError::internal());
                }
            }
        }
        if let Some((out, path, hash, len)) = &mut file
            && !chunk.is_empty()
        {
            *len += chunk.len() as u64;
            if *len > MAX_PACKAGE as u64 {
                return failed(Some(path.clone()), too_large());
            }
            hash.update(&chunk);
            if let Err(error) = out.write_all(&chunk).await {
                log::error!("plugins: cannot store an upload: {error}");
                return failed(Some(path.clone()), ApiError::internal());
            }
        }
    }
    let path = file.as_ref().map(|(_, path, _, _)| path.clone());
    if !parser.done() {
        return failed(path, bad());
    }
    if let Some((mut out, path, hash, len)) = file {
        if let Err(error) = out.flush().await {
            log::error!("plugins: cannot store an upload: {error}");
            return failed(Some(path), ApiError::internal());
        }
        form.file = Some(Package { path, len, sha256: crate::random::hex(&hash.finalize()) });
    }
    form.password = match fields.password {
        Some(bytes) => Some(String::from_utf8(bytes).map_err(|_| ApiError::field("password", "Wrong password."))?),
        None => None,
    };
    form.allow_downgrade = fields.allow_downgrade.is_some_and(|value| matches!(&value[..], b"1" | b"true" | b"yes" | b"on"));
    Ok(form)
}

fn boundary(content_type: &str) -> Option<&str> {
    if !content_type.to_ascii_lowercase().starts_with("multipart/form-data") {
        return None;
    }
    content_type
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| key.eq_ignore_ascii_case("boundary"))
        .map(|(_, value)| value.trim_matches('"'))
        .filter(|boundary| !boundary.is_empty() && boundary.len() <= 70)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    File,
    Password,
    AllowDowngrade,
    Other,
}

/// The small fields as they arrive; the file's bytes go to the caller's chunk.
#[derive(Default)]
struct Fields {
    files: usize,
    password: Option<Vec<u8>>,
    allow_downgrade: Option<Vec<u8>>,
}

impl Fields {
    /// `bytes` of `field`; an empty slice starts the part.
    fn take(&mut self, field: Field, bytes: &[u8], chunk: &mut Vec<u8>) -> ApiResult<()> {
        let small = match field {
            Field::File => {
                if bytes.is_empty() {
                    self.files += 1;
                    if self.files > 1 {
                        return Err(ApiError::bad_request("Send one package."));
                    }
                }
                chunk.extend_from_slice(bytes);
                return Ok(());
            }
            Field::Password => &mut self.password,
            Field::AllowDowngrade => &mut self.allow_downgrade,
            Field::Other => return Ok(()),
        };
        let value = small.get_or_insert_with(Vec::new);
        value.extend_from_slice(bytes);
        if value.len() > MAX_FIELD {
            return Err(bad());
        }
        Ok(())
    }
}

enum Step {
    /// Before the first delimiter.
    Preamble,
    /// Just after a delimiter: `--` ends the form, CRLF starts a part.
    Delimiter,
    Head,
    Part(Field),
    Done,
}

/// A multipart body, fed in pieces of any size.
struct Parser {
    /// CRLF `--` boundary: the body is read as if it began with CRLF, so the first
    /// delimiter looks like the others.
    delimiter: Vec<u8>,
    buffer: Vec<u8>,
    step: Step,
}

impl Parser {
    fn new(boundary: &str) -> Self {
        Self { delimiter: format!("\r\n--{boundary}").into_bytes(), buffer: b"\r\n".to_vec(), step: Step::Preamble }
    }

    fn done(&self) -> bool {
        matches!(self.step, Step::Done)
    }

    /// Takes `data`; `out(field, bytes)` gets each part's bytes, never empty, and an empty
    /// slice once as the part starts.
    fn feed(&mut self, data: &[u8], out: &mut dyn FnMut(Field, &[u8]) -> ApiResult<()>) -> ApiResult<()> {
        if self.done() {
            return Ok(());
        }
        self.buffer.extend_from_slice(data);
        loop {
            match self.step {
                Step::Preamble => match find(&self.buffer, &self.delimiter) {
                    Some(at) => {
                        self.buffer.drain(..at + self.delimiter.len());
                        self.step = Step::Delimiter;
                    }
                    None => {
                        let keep = self.delimiter.len() - 1;
                        let cut = self.buffer.len().saturating_sub(keep);
                        self.buffer.drain(..cut);
                        return Ok(());
                    }
                },
                Step::Delimiter => {
                    if self.buffer.len() < 2 {
                        return Ok(());
                    }
                    match &self.buffer[..2] {
                        b"--" => {
                            self.step = Step::Done;
                            self.buffer.clear();
                            return Ok(());
                        }
                        b"\r\n" => {
                            self.buffer.drain(..2);
                            self.step = Step::Head;
                        }
                        _ => return Err(bad()),
                    }
                }
                Step::Head => {
                    let Some(end) = find(&self.buffer, b"\r\n\r\n") else {
                        return if self.buffer.len() > MAX_PART_HEAD { Err(bad()) } else { Ok(()) };
                    };
                    if end > MAX_PART_HEAD {
                        return Err(bad());
                    }
                    let head = std::str::from_utf8(&self.buffer[..end]).map_err(|_| bad())?;
                    let field = match part_name(head).as_deref() {
                        Some("file") => Field::File,
                        Some("password") => Field::Password,
                        Some("allow_downgrade") => Field::AllowDowngrade,
                        _ => Field::Other,
                    };
                    self.buffer.drain(..end + 4);
                    out(field, &[])?;
                    self.step = Step::Part(field);
                }
                Step::Part(field) => match find(&self.buffer, &self.delimiter) {
                    Some(at) => {
                        if at > 0 {
                            out(field, &self.buffer[..at])?;
                        }
                        self.buffer.drain(..at + self.delimiter.len());
                        self.step = Step::Delimiter;
                    }
                    None => {
                        // The end may hold the start of a delimiter.
                        let cut = self.buffer.len().saturating_sub(self.delimiter.len() - 1);
                        if cut > 0 {
                            out(field, &self.buffer[..cut])?;
                        }
                        self.buffer.drain(..cut);
                        return Ok(());
                    }
                },
                Step::Done => return Ok(()),
            }
        }
    }
}

fn part_name(head: &str) -> Option<String> {
    head.lines().find(|line| line.to_ascii_lowercase().starts_with("content-disposition:")).and_then(|line| {
        line.split(';').filter_map(|part| part.trim().split_once('=')).find(|(key, _)| *key == "name").map(|(_, value)| value.trim_matches('"').to_owned())
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const FORM: &[u8] = b"------WebKitFormBoundaryAbC\r\nContent-Disposition: form-data; name=\"file\"; filename=\"p.tar\"\r\nContent-Type: application/x-tar\r\n\r\nPK\x03\x04\r\n--not-it\r\n\r\n------WebKitFormBoundaryAbC\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter22\r\n------WebKitFormBoundaryAbC\r\nContent-Disposition: form-data; name=\"allow_downgrade\"\r\n\r\n1\r\n------WebKitFormBoundaryAbC--\r\n";

    fn headers(content_type: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        headers
    }

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kh-upload-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The same form in pieces of every size: a delimiter split anywhere is still found.
    #[test]
    fn reads_a_browser_form_in_any_pieces() {
        for size in [1, 2, 3, 7, 30, 64, FORM.len()] {
            let mut parser = Parser::new("----WebKitFormBoundaryAbC");
            let mut fields = Fields::default();
            let mut file = Vec::new();
            for piece in FORM.chunks(size) {
                parser.feed(piece, &mut |field, bytes| fields.take(field, bytes, &mut file)).unwrap();
            }
            assert!(parser.done(), "{size}");
            assert_eq!(file, b"PK\x03\x04\r\n--not-it\r\n", "{size}");
            assert_eq!(fields.password.as_deref(), Some(&b"hunter22"[..]));
            assert_eq!(fields.allow_downgrade.as_deref(), Some(&b"1"[..]));
        }
    }

    #[tokio::test]
    async fn stores_the_file_privately_and_removes_it_after() {
        use std::os::unix::fs::PermissionsExt;
        let state = dir("store");
        let form = read(&state, &headers("multipart/form-data; boundary=----WebKitFormBoundaryAbC"), Body::from(FORM)).await.unwrap();
        let file = form.file.unwrap();
        assert_eq!(std::fs::read(file.path()).unwrap(), b"PK\x03\x04\r\n--not-it\r\n");
        assert_eq!(file.sha256(), kaonic_hub_installer::sha256_hex(b"PK\x03\x04\r\n--not-it\r\n"));
        assert_eq!((form.password.as_deref(), form.allow_downgrade), (Some("hunter22"), true));
        assert_eq!(std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(state.join("uploads")).unwrap().permissions().mode() & 0o777, 0o700);
        let path = file.path().to_owned();
        drop(file);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn refuses_what_is_not_a_form_and_leaves_nothing() {
        let state = dir("refuse");
        assert!(read(&state, &HeaderMap::new(), Body::from("x")).await.is_err());
        let form = headers("multipart/form-data; boundary=b");
        assert!(read(&state, &form, Body::from("--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nunterminated")).await.is_err());
        assert!(read(&state, &headers("application/zip"), Body::from("PK")).await.is_err());
        let two = "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\na\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nb\r\n--b--\r\n";
        assert!(read(&state, &form, Body::from(two)).await.is_err());
        assert_eq!(std::fs::read_dir(state.join("uploads")).unwrap().count(), 0, "a refused upload leaves no file");
    }

    #[tokio::test]
    async fn a_package_over_the_limit_is_refused_as_it_arrives() {
        let state = dir("large");
        let form = headers("multipart/form-data; boundary=b");
        let head = "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n";
        // A body that never ends: it is refused once past the limit, not read whole.
        let chunk = axum::body::Bytes::from(vec![0u8; 1 << 20]);
        let endless = futures_like(head.as_bytes().to_vec(), chunk);
        let error = read(&state, &form, Body::new(endless)).await.err().unwrap();
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(std::fs::read_dir(state.join("uploads")).unwrap().count(), 0);
    }

    /// A body of `head` and then `chunk` again and again.
    fn futures_like(head: Vec<u8>, chunk: axum::body::Bytes) -> impl http_body::Body<Data = axum::body::Bytes, Error = std::io::Error> + Send + 'static {
        struct Endless(Option<Vec<u8>>, axum::body::Bytes);
        impl http_body::Body for Endless {
            type Data = axum::body::Bytes;
            type Error = std::io::Error;
            fn poll_frame(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                let next = match self.0.take() {
                    Some(head) => axum::body::Bytes::from(head),
                    None => self.1.clone(),
                };
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(next))))
            }
        }
        Endless(Some(head), chunk)
    }
}
