//! Read a single encrypted credential using its environment-scoped record key.
use anyhow::{anyhow, ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use rusqlite::{params, Connection, OpenFlags};
use serde::{de::Error, Deserialize, Deserializer};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"KeyHeron/v1/credential\0";
pub const MAX_CREDENTIAL: usize = 16_384;

fn fixed_base64<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
    let input = Zeroizing::new(String::deserialize(d)?);
    let decoded = Zeroizing::new(
        STANDARD
            .decode(input.as_bytes())
            .map_err(|_| D::Error::custom("凭据绑定格式无效"))?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| D::Error::custom("凭据绑定长度无效"))
}

fn record_key<'de, D: Deserializer<'de>>(d: D) -> Result<Arc<Zeroizing<[u8; 32]>>, D::Error> {
    Ok(Arc::new(Zeroizing::new(fixed_base64(d)?)))
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    db: PathBuf,
    #[serde(rename = "ref")]
    reference: String,
    #[serde(deserialize_with = "fixed_base64")]
    salt: [u8; 16],
    #[serde(deserialize_with = "record_key")]
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl Binding {
    pub fn validate(&self, environment: &str) -> Result<()> {
        let (env, name) = self
            .reference
            .split_once('/')
            .ok_or_else(|| anyhow!("加密凭据引用无效"))?;
        ensure!(
            self.db.is_absolute()
                && env == environment
                && (1..=64).contains(&name.len())
                && name.as_bytes()[0].is_ascii_alphanumeric()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)),
            "加密凭据路径或环境引用无效"
        );
        Ok(())
    }

    fn aad(&self) -> Vec<u8> {
        [DOMAIN, &self.salt, b"\0", self.reference.as_bytes()].concat()
    }

    pub fn read(&self) -> Result<Zeroizing<Vec<u8>>> {
        let unavailable = || anyhow!("加密凭据不可用或认证失败");
        let metadata = self.db.symlink_metadata().map_err(|_| unavailable())?;
        ensure!(metadata.is_file(), "加密凭据库不是普通文件");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no arguments or preconditions.
            let uid = unsafe { libc::geteuid() };
            ensure!(
                metadata.mode() & 0o077 == 0 && (metadata.uid() == 0 || metadata.uid() == uid),
                "凭据库须为受信账户独占的普通文件"
            );
        }
        // SQLite NOFOLLOW covers intermediate links too (e.g. /var on macOS).
        let directory = self
            .db
            .parent()
            .ok_or_else(unavailable)?
            .canonicalize()
            .map_err(|_| unavailable())?;
        let file = directory.join(self.db.file_name().ok_or_else(unavailable)?);
        let conn = Connection::open_with_flags(
            file,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| unavailable())?;
        conn.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")
            .map_err(|_| unavailable())?;
        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT c.nonce,c.ciphertext FROM vault_credentials c, vault_meta m
             WHERE c.ref=?1 AND m.id=1 AND m.version=1 AND m.salt=?2
               AND typeof(c.nonce)='blob' AND length(c.nonce)=12
               AND typeof(c.ciphertext)='blob' AND length(c.ciphertext) BETWEEN 17 AND ?3",
                params![
                    self.reference,
                    &self.salt[..],
                    MAX_CREDENTIAL + AES_256_GCM.tag_len()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| unavailable())?;
        let mut raw = Zeroizing::new(ciphertext);
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, self.key.as_slice()).map_err(|_| unavailable())?,
        );
        let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| unavailable())?;
        let len = key
            .open_in_place(nonce, Aad::from(self.aad()), &mut raw)
            .map_err(|_| unavailable())?
            .len();
        raw.truncate(len);
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use uuid::Uuid;

    #[test]
    fn authenticate_python_ciphertext_and_reload_rotation() -> Result<()> {
        let path = std::env::temp_dir().join(format!("keyheron-vault-{}.sqlite3", Uuid::new_v4()));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let binding: Binding = serde_json::from_value(serde_json::json!({
            "db": path, "ref": "DEV/test",
            "salt": STANDARD.encode(std::array::from_fn::<_, 16, _>(|i| i as u8)),
            "key": STANDARD.encode(std::array::from_fn::<_, 32, _>(|i| i as u8)),
        }))?;
        binding.validate("DEV")?;
        assert!(binding.validate("PROD").is_err());
        let sql = Connection::open(&path)?;
        sql.execute_batch(
            "CREATE TABLE vault_meta(id INTEGER PRIMARY KEY, version INTEGER, salt BLOB);
             CREATE TABLE vault_credentials(ref TEXT PRIMARY KEY, nonce BLOB, ciphertext BLOB);",
        )?;
        sql.execute(
            "INSERT INTO vault_meta VALUES (1,1,?1)",
            [&binding.salt[..]],
        )?;
        // Known-answer vectors from Python cryptography's AESGCM, using synthetic keys.
        let vectors = [
            (
                1,
                "YKbMiDaRUXMjWjRKmItVmXBhQ11zcAuNr8WGnjULtSGp",
                "upstream-test-one",
            ),
            (
                2,
                "vAFKHMAuvvzfZERlAjOOFVv065FTbxxSUxE+wSZEPQ==",
                "updated-fixture",
            ),
        ];
        for (counter, cipher, expected) in vectors {
            let mut nonce = [0u8; 12];
            nonce[11] = counter;
            sql.execute(
                "INSERT OR REPLACE INTO vault_credentials VALUES (?1,?2,?3)",
                params![
                    binding.reference,
                    nonce.as_slice(),
                    STANDARD.decode(cipher)?
                ],
            )?;
            assert_eq!(binding.read()?.as_slice(), expected.as_bytes());
        }
        sql.execute("UPDATE vault_meta SET version=2", [])?;
        assert!(binding.read().is_err());
        sql.execute("UPDATE vault_meta SET version=1", [])?;
        let other = Binding {
            reference: "DEV/other".into(),
            ..binding.clone()
        };
        sql.execute("UPDATE vault_credentials SET ref=?1", [&other.reference])?;
        assert!(other.read().is_err());
        assert!(binding.read().is_err());
        sql.execute(
            "UPDATE vault_credentials SET ref=?1, ciphertext=zeroblob(32)",
            [&binding.reference],
        )?;
        assert!(binding.read().is_err());
        drop(sql);
        std::fs::remove_file(path)?;
        assert!(binding.read().is_err());
        assert!(!binding.db.exists());
        Ok(())
    }
}
