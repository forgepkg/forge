//! The object store the files live in: Forge's S3 bucket
//! ([`forge_storage::BlobStore`]), or memory in tests ([`MemoryObjects`]).

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use bytes::Bytes;
use forge_storage::BlobStore;

/// An object a listing found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub key: String,
    pub size: u64,
    /// Changes whenever the object is replaced (the cache key of a file).
    pub etag: Option<String>,
}

/// What the statistics need of an object store.
#[async_trait::async_trait]
pub trait Objects: Send + Sync + 'static {
    /// Store `body` at `key`, replacing what is there.
    async fn put(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;
    /// The object at `key`, or `None` when there is none (any more).
    async fn get(&self, key: &str) -> anyhow::Result<Option<Bytes>>;
    /// Every object whose key starts with `prefix`.
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<Listed>>;
    /// The "directories" right under `prefix` (which ends with `/`): the
    /// distinct key prefixes up to the next `/`, each ending with it.
    async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>>;
    /// Delete the object at `key`; a missing one is no error.
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl Objects for BlobStore {
    async fn put(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        Ok(self.put_bytes(key, body).await?)
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<Bytes>> {
        Ok(self.get_bytes(key).await?)
    }

    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<Listed>> {
        Ok(BlobStore::list(self, prefix, None)
            .await?
            .objects
            .into_iter()
            .map(|o| Listed {
                key: o.key,
                size: o.size,
                etag: o.etag,
            })
            .collect())
    }

    async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        Ok(BlobStore::list(self, prefix, Some("/")).await?.prefixes)
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        Ok(BlobStore::delete(self, key).await?)
    }
}

/// An object store in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryObjects {
    objects: Mutex<BTreeMap<String, (Bytes, u64)>>,
}

impl MemoryObjects {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, (Bytes, u64)>> {
        self.objects.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The keys stored, in order.
    pub fn keys(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }
}

#[async_trait::async_trait]
impl Objects for MemoryObjects {
    async fn put(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        let mut objects = self.lock();
        let version = objects.get(key).map_or(1, |(_, v)| v + 1);
        objects.insert(key.to_string(), (body.into(), version));
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<Bytes>> {
        Ok(self.lock().get(key).map(|(body, _)| body.clone()))
    }

    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<Listed>> {
        Ok(self
            .lock()
            .range(prefix.to_string()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, (body, version))| Listed {
                key: key.clone(),
                size: body.len() as u64,
                etag: Some(version.to_string()),
            })
            .collect())
    }

    async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let mut dirs: Vec<String> = Vec::new();
        for listed in self.list(prefix).await? {
            if let Some(end) = listed.key[prefix.len()..].find('/') {
                let dir = &listed.key[..prefix.len() + end + 1];
                if dirs.last().map(String::as_str) != Some(dir) {
                    dirs.push(dir.to_string());
                }
            }
        }
        Ok(dirs)
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.lock().remove(key);
        Ok(())
    }
}
