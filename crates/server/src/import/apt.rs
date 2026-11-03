//! An apt repository as an import's source: Nexus' apt hosted repository
//! (`<nexus>/repository/<name>`), a static repository a web server serves
//! (made with `dpkg-scanpackages` or `apt-ftparchive`), or another Forge.
//! What its files say is the apt format's ([`forge_format_apt::import`]);
//! this sends the requests, through the shared [`UpstreamHttp`] client
//! (timeouts, size caps, no cloud-metadata targets), with the credentials,
//! as Basic authentication, to the source's origin alone.
//!
//! * [`AptSource::release`]: `dists/<distribution>/InRelease`, else
//!   `Release`. Given the source's public keys ([`Keyring`]), the import
//!   reads only a `Release` one of them signed: `InRelease`'s cleartext
//!   signature, or `Release.gpg`'s detached one.
//! * [`AptSource::packages`]: a `Packages` index, from its
//!   `by-hash/SHA256/<sha256>` copy where `Release` says `Acquire-By-Hash`
//!   (so a `Release` and an index of two generations never meet), checked
//!   against the size and SHA-256 `Release` lists before it is read.
//! * [`AptSource::download`]: a `.deb`, from `<url>/<Filename>`.

use forge_core::net::upstream::{Origin, RequestClass, SpooledBody, UpstreamAuth, UpstreamHttp};
use forge_crypto::{ExposeSecret, PlaintextSecret};
use forge_format_apt::import::{self as apt, Entry, Index, Release};
use pgp::composed::{
    CleartextSignedMessage, Deserializable, DetachedSignature, PublicOrSecret, SignedPublicKey,
};
use pgp::types::KeyDetails;
use reqwest::StatusCode;

use super::SourceError;

/// The most public keys an import is given.
const MAX_KEYS: usize = 16;

/// The public keys a source's `Release` must be signed with.
#[derive(Clone)]
pub struct Keyring {
    keys: Vec<SignedPublicKey>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.fingerprints()).finish()
    }
}

impl Keyring {
    /// Read ASCII-armored public keys (one block, or several). A secret key
    /// is refused, and so is a key whose self-signatures do not verify.
    pub fn parse(armored: &str) -> Result<Keyring, String> {
        let armored = armored.trim();
        if !armored.starts_with("-----BEGIN PGP") {
            return Err(
                "the public key is not ASCII-armored (-----BEGIN PGP PUBLIC KEY BLOCK-----)".into(),
            );
        }
        let mut keys = Vec::new();
        let mut rest = armored;
        // One armor block after the other (`gpg --export --armor a b` writes
        // one; a key pasted after another, two).
        while let Some(start) = rest.find("-----BEGIN PGP") {
            let block = &rest[start..];
            let end = block
                .find("-----END PGP")
                .and_then(|at| block[at..].find('\n').map(|nl| at + nl + 1))
                .unwrap_or(block.len());
            let (parsed, _) = PublicOrSecret::from_armor_many(&block.as_bytes()[..end])
                .map_err(|e| format!("the public key cannot be read: {e}"))?;
            for key in parsed {
                match key.map_err(|e| format!("the public key cannot be read: {e}"))? {
                    PublicOrSecret::Public(key) => {
                        key.verify_bindings().map_err(|e| {
                            format!("the public key's self-signatures do not verify: {e}")
                        })?;
                        keys.push(key);
                    }
                    PublicOrSecret::Secret(_) => return Err(
                        "that is a secret key: give the source's public key (gpg --export --armor)"
                            .into(),
                    ),
                }
            }
            rest = &block[end..];
        }
        if keys.is_empty() {
            return Err("the public key block holds no key".into());
        }
        if keys.len() > MAX_KEYS {
            return Err(format!("give at most {MAX_KEYS} public keys"));
        }
        Ok(Keyring { keys })
    }

    /// The keys' fingerprints, uppercase hex.
    pub fn fingerprints(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|key| hex::encode_upper(key.fingerprint().as_bytes()))
            .collect()
    }

    /// Whether one of the keys (a primary key or a subkey) made one of the
    /// message's signatures.
    fn signed_cleartext(&self, message: &CleartextSignedMessage) -> bool {
        self.keys.iter().any(|key| {
            message.verify(key).is_ok()
                || key
                    .public_subkeys
                    .iter()
                    .any(|subkey| message.verify(subkey).is_ok())
        })
    }

    /// Whether one of the keys made one of the detached `signatures` of
    /// `data`.
    fn signed_detached(&self, signatures: &[DetachedSignature], data: &[u8]) -> bool {
        signatures.iter().any(|signature| {
            self.keys.iter().any(|key| {
                signature.verify(key, data).is_ok()
                    || key
                        .public_subkeys
                        .iter()
                        .any(|subkey| signature.verify(subkey, data).is_ok())
            })
        })
    }
}

/// An apt repository and one of its distributions.
pub struct AptSource {
    http: UpstreamHttp,
    /// The repository's base URL, without a trailing `/`.
    url: String,
    distribution: String,
    username: Option<String>,
    password: Option<PlaintextSecret>,
    keys: Option<Keyring>,
    /// The `Server` header the source answered [`Self::release`] with.
    server: std::sync::Mutex<Option<String>>,
}

impl AptSource {
    /// The repository at `url`, its `distribution`, read with the
    /// credentials when given; its `Release` checked against `keys` when
    /// given.
    pub fn new(
        http: UpstreamHttp,
        url: &str,
        distribution: &str,
        username: Option<String>,
        password: Option<PlaintextSecret>,
        keys: Option<Keyring>,
    ) -> Self {
        AptSource {
            http,
            url: url.trim_end_matches('/').to_string(),
            distribution: distribution.to_string(),
            username,
            password,
            keys,
            server: std::sync::Mutex::new(None),
        }
    }

    /// The `Server` header the source answered [`Self::release`] with.
    pub fn server(&self) -> Option<String> {
        self.server
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set_server(&self, server: Option<String>) {
        *self
            .server
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = server;
    }

    /// The Basic credentials, for the source's origin only.
    fn auth(&self) -> Option<UpstreamAuth<'_>> {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => Some(UpstreamAuth {
                origin: Origin::of(&self.url),
                username,
                password: password.expose_secret(),
                bearer: false,
            }),
            _ => None,
        }
    }

    /// Where the source serves `path` (below its base URL), each segment
    /// percent-encoded.
    pub fn file_url(&self, path: &str) -> Option<String> {
        forge_format_apt::proxy::upstream_url(&format!("{}/", self.url), path)
    }

    /// The URL of `path` below `dists/<distribution>/`.
    fn dists_url(&self, path: &str) -> Option<String> {
        self.file_url(&format!("dists/{}/{path}", self.distribution))
    }

    /// GET `url`: its `Server` header and body, or `None` when the source
    /// does not have it. A refusal of the credentials, a server error and a
    /// failed transfer are errors.
    async fn get_document(
        &self,
        url: &str,
    ) -> Result<Option<(Option<String>, Vec<u8>)>, SourceError> {
        let response = self
            .http
            .get(url, RequestClass::Metadata, self.auth().as_ref())
            .await
            .map_err(|e| SourceError::of(e, url))?;
        let status = response.status();
        let server = response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        match status {
            s if s.is_success() => {}
            StatusCode::NOT_FOUND | StatusCode::GONE => return Ok(None),
            s => return Err(SourceError::status(s, url)),
        }
        let config = self.http.config();
        let body = SpooledBody::read(
            response,
            url,
            config.max_metadata_bytes,
            config.spool_memory_bytes,
        )
        .await
        .map_err(|e| SourceError::of(e, url))?;
        self.http.count_bytes(body.len());
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut body.into_reader()?, &mut out)?;
            Ok(out)
        })
        .await
        .map_err(|e| SourceError::Invalid(e.to_string()))?
        .map_err(|e| SourceError::Unreachable(format!("reading {url}: {e}")))?;
        Ok(Some((server, bytes)))
    }

    /// The distribution's `Release`: `InRelease`'s text, else `Release`.
    /// With keys, only one of them signed: `InRelease`'s cleartext
    /// signature, or `Release.gpg`. Records the `Server` header.
    pub async fn release(&self) -> Result<Release, SourceError> {
        let invalid = |e: String| SourceError::Invalid(e);
        let in_release = self.dists_url("InRelease").ok_or_else(|| {
            invalid(format!(
                "{} is no http(s) URL of an apt repository",
                self.url
            ))
        })?;
        if let Some((server, body)) = self.get_document(&in_release).await? {
            self.set_server(server);
            let text = String::from_utf8(body)
                .map_err(|_| invalid(format!("{in_release} is not UTF-8")))?;
            let mut signed =
                apt::cleartext(&text).map_err(|e| invalid(format!("{in_release}: {e}")))?;
            if let Some(keys) = &self.keys {
                let (message, _) = CleartextSignedMessage::from_string(&text).map_err(|e| {
                    invalid(format!("{in_release}: its signature cannot be read: {e}"))
                })?;
                if !keys.signed_cleartext(&message) {
                    return Err(invalid(format!(
                        "{in_release} is not signed by the public key the import was given ({})",
                        keys.fingerprints().join(", ")
                    )));
                }
                // What was signed is what is read.
                signed = message.signed_text().replace("\r\n", "\n");
            }
            return Release::parse(&signed).map_err(|e| invalid(format!("{in_release}: {e}")));
        }
        let release = self.dists_url("Release").unwrap_or_default();
        let Some((server, body)) = self.get_document(&release).await? else {
            return Err(invalid(format!(
                "the source has neither {in_release} nor {release}: is {} one of its \
                 distributions?",
                self.distribution
            )));
        };
        self.set_server(server);
        if let Some(keys) = &self.keys {
            let detached = self.dists_url("Release.gpg").unwrap_or_default();
            let Some((_, signature)) = self.get_document(&detached).await? else {
                return Err(invalid(format!(
                    "the source's Release is not signed: it serves neither {in_release} nor \
                     {detached}"
                )));
            };
            let signatures =
                detached_signatures(&signature).map_err(|e| invalid(format!("{detached}: {e}")))?;
            if !keys.signed_detached(&signatures, &body) {
                return Err(invalid(format!(
                    "{release} is not signed by the public key the import was given ({})",
                    keys.fingerprints().join(", ")
                )));
            }
        }
        let text =
            String::from_utf8(body).map_err(|_| invalid(format!("{release} is not UTF-8")))?;
        Release::parse(&text).map_err(|e| invalid(format!("{release}: {e}")))
    }

    /// Every entry of `index`: the first of its files the source serves
    /// (its `by-hash` copy first, where `release` says `Acquire-By-Hash`),
    /// checked against the size and SHA-256 `Release` lists for it, then
    /// inflated and read. A file that does not match fails the scan, and so
    /// does an index whose entries take more than
    /// [`apt::MAX_ENTRIES_BYTES`] of memory: the scan keeps them while it
    /// is in the index.
    pub async fn packages(
        &self,
        release: &Release,
        index: &Index,
    ) -> Result<Vec<Entry>, SourceError> {
        for file in &index.files {
            let mut paths = Vec::with_capacity(2);
            if release.acquire_by_hash {
                paths.push(file.by_hash());
            }
            paths.push(file.path.clone());
            for path in paths {
                let url = self.dists_url(&path).unwrap_or_default();
                let Some((_, bytes)) = self.get_document(&url).await? else {
                    continue;
                };
                let file = file.clone();
                return tokio::task::spawn_blocking(move || {
                    file.check(&bytes)
                        .map_err(|e| format!("the index does not match Release: {e}"))?;
                    apt::read_packages(apt::inflate(&bytes)).map_err(|e| format!("{url}: {e}"))
                })
                .await
                .map_err(|e| SourceError::Invalid(format!("reading the index: {e}")))?
                .map_err(SourceError::Invalid);
            }
        }
        Err(SourceError::Invalid(format!(
            "Release lists the index of {} {}, but the source serves none of {}",
            index.component,
            index.architecture,
            index
                .files
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    /// GET the package at `filename` (below the base URL), streamed by the
    /// caller; `None` when the source does not have it.
    pub async fn download(&self, filename: &str) -> Result<Option<reqwest::Response>, SourceError> {
        let url = self.file_url(filename).ok_or_else(|| {
            SourceError::Invalid(format!("{filename:?} is no path below the repository"))
        })?;
        let response = self
            .http
            .get(&url, RequestClass::Download, self.auth().as_ref())
            .await
            .map_err(|e| SourceError::of(e, &url))?;
        match response.status() {
            s if s.is_success() => Ok(Some(response)),
            StatusCode::NOT_FOUND | StatusCode::GONE => Ok(None),
            s => Err(SourceError::status(s, &url)),
        }
    }
}

/// The detached signatures of a `Release.gpg`, ASCII-armored or binary.
fn detached_signatures(bytes: &[u8]) -> Result<Vec<DetachedSignature>, String> {
    let read = |e: pgp::errors::Error| format!("its signatures cannot be read: {e}");
    let signatures: Vec<DetachedSignature> = if bytes.trim_ascii_start().starts_with(b"-----BEGIN")
    {
        let (signatures, _) = DetachedSignature::from_armor_many(bytes).map_err(read)?;
        signatures.collect::<Result<_, _>>().map_err(read)?
    } else {
        DetachedSignature::from_bytes_many(bytes)
            .map_err(read)?
            .collect::<Result<_, _>>()
            .map_err(read)?
    };
    if signatures.is_empty() {
        return Err("it holds no signature".into());
    }
    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexes::signing::{self, Key};

    #[test]
    fn a_keyring_takes_public_keys_and_verifies_both_signatures() {
        let a = Key::generate("Source <source@example.com>").unwrap();
        let b = Key::generate("Other <other@example.com>").unwrap();
        let info = a.info().unwrap();
        let keys = Keyring::parse(&info.public_key).unwrap();
        assert_eq!(keys.fingerprints(), std::slice::from_ref(&info.fingerprint));

        let text = "Origin: Acme\nSuite: stable\n";
        let signed = signing::sign_cleartext(std::slice::from_ref(&a), text).unwrap();
        let (message, _) = CleartextSignedMessage::from_string(&signed).unwrap();
        assert!(keys.signed_cleartext(&message));
        let other = signing::sign_cleartext(std::slice::from_ref(&b), text).unwrap();
        let (message, _) = CleartextSignedMessage::from_string(&other).unwrap();
        assert!(!keys.signed_cleartext(&message));

        let detached = signing::sign_detached(std::slice::from_ref(&a), text.as_bytes()).unwrap();
        let signatures = detached_signatures(detached.as_bytes()).unwrap();
        assert!(keys.signed_detached(&signatures, text.as_bytes()));
        assert!(!keys.signed_detached(&signatures, b"Origin: Mallory\n"));

        // Two keys, one block each, pasted one after the other.
        let both = format!("{}\n{}", info.public_key, b.info().unwrap().public_key);
        assert_eq!(Keyring::parse(&both).unwrap().fingerprints().len(), 2);
    }

    #[test]
    fn a_keyring_refuses_what_is_no_public_key() {
        let key = Key::generate("Source <source@example.com>").unwrap();
        let secret = key.to_sealable().unwrap();
        let err = Keyring::parse(&secret).unwrap_err();
        assert!(err.contains("secret key"), "{err}");
        for bad in [
            "",
            "not a key",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxx\n",
        ] {
            assert!(Keyring::parse(bad).is_err(), "{bad}");
        }
    }
}
