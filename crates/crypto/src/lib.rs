//! Secret encryption at rest — double envelope encryption (spec §12.5).
//!
//! Implements the three-layer key hierarchy and the AEAD envelope used to
//! encrypt small secret values (the proxy `upstream_password` first; future
//! secrets adopt the same seam):
//!
//! ```text
//! ROOT (env/file today, KMS later)  — wraps →  KEK  — wraps →  DEK  — seals →  secret
//! ```
//!
//! * [`envelope`] — the versioned, self-describing AEAD blob format
//!   (`format_version | algorithm | key_version | nonce | ciphertext+tag`) and
//!   the [`envelope::AeadBinding`] AAD that ties a ciphertext to its
//!   `(table, column, row_pk)` so a blob copied into another row/column fails
//!   to decrypt (swap-attack defense).
//! * [`kms`] — the [`kms::KmsProvider`] root-layer abstraction plus the
//!   [`kms::StaticRootProvider`] (32-byte root key from an env var or file,
//!   base64). A real AWS KMS provider is a later, additive impl of the trait.
//! * [`store`] — the [`store::KeyStore`] persistence seam for **wrapped**
//!   KEK/DEK rows (`encryption_key` table; `forge-db` provides the Postgres
//!   impl) and an [`store::InMemoryKeyStore`] for hermetic tests.
//! * [`service`] — the [`service::EnvelopeService`]: seal/open with a bounded,
//!   TTL'd, zeroizing cache of unwrapped keys, idempotent key bootstrap, and
//!   per-layer rotation (DEK / KEK / root).
//! * [`secret`] — the zeroizing plaintext/key-byte newtypes.
//!
//! No unwrapped key material is ever persisted: the authoritative state is the
//! wrapped rows in Postgres plus the root held outside the database, so every
//! instance can reconstruct every key (§2.1-compliant; the unwrapped-key cache
//! holds only derivable material for a short TTL and zeroizes on drop).

pub mod envelope;
pub mod error;
pub mod kms;
pub mod secret;
pub mod service;
pub mod store;

pub use envelope::{AeadBinding, Algorithm};
pub use error::CryptoError;
pub use kms::{KmsProvider, StaticRootProvider};
pub use secret::{KeyBytes, PlaintextSecret};
pub use service::{EnvelopeService, EnvelopeServiceConfig};
pub use store::{InMemoryKeyStore, KeyLayer, KeyRecord, KeyState, KeyStore, NewKeyRecord};
