//! 传输层解密：Chunk 帧负载 = nonce(12) + ChaCha20-Poly1305 密文(chunk_len + tag16)。
//! 与 slimSync / e2e-tools zenoh_pub_enc 的加密契约一致（slim-common framing + chacha20poly1305 0.10）。

use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::path::Path;

/// 帧负载前缀 nonce 长度。
pub const NONCE_LEN: usize = 12;
/// ChaCha20-Poly1305 认证标签长度。
pub const TAG_LEN: usize = 16;

pub struct Decryptor {
    cipher: ChaCha20Poly1305,
}

impl Decryptor {
    pub fn new(key: [u8; 32]) -> Decryptor {
        Decryptor {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }

    /// 从 32 字节 hex 密钥构造。
    pub fn from_key_hex(hex_str: &str) -> Result<Decryptor> {
        let key = hex::decode(hex_str.trim()).context("key_hex 非法 hex")?;
        if key.len() != 32 {
            bail!("密钥必须 32 字节，实际 {}", key.len());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        Ok(Decryptor::new(k))
    }

    /// 从密钥文件（32B 原始字节）构造。
    pub fn from_key_file(path: &Path) -> Result<Decryptor> {
        let bytes =
            std::fs::read(path).with_context(|| format!("读取密钥失败: {}", path.display()))?;
        if bytes.len() != 32 {
            bail!("密钥文件必须 32 字节，实际 {}", bytes.len());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        Ok(Decryptor::new(k))
    }

    /// 解密一个 chunk 帧负载：payload = nonce(12) + 密文(chunk_len + tag16)。
    /// 返回明文 chunk 字节（长度 == chunk_len）。
    pub fn decrypt_chunk_payload(&self, payload: &[u8], chunk_len: u32) -> Result<Vec<u8>> {
        if payload.len() < NONCE_LEN {
            bail!("负载过短（无 nonce）：{}", payload.len());
        }
        let expected = NONCE_LEN + chunk_len as usize + TAG_LEN;
        if payload.len() != expected {
            bail!(
                "负载长度不符：期望 {}（chunk_len={}），实际 {}",
                expected,
                chunk_len,
                payload.len()
            );
        }
        let nonce = Nonce::from_slice(&payload[..NONCE_LEN]);
        let mut ct = payload[NONCE_LEN..].to_vec();
        self.cipher
            .decrypt_in_place(nonce, &[], &mut ct)
            .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 认证失败（密钥不符或数据损坏）"))?;
        Ok(ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead;

    #[test]
    fn roundtrip_encrypted_chunk() {
        let key = [7u8; 32];
        let d = Decryptor::new(key);
        // 模拟发送端：nonce + 明文 → 密文+tag
        let plain = b"GET /api/orders/1 HTTP/1.1".to_vec();
        let mut payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&payload);
        let ct = cipher.encrypt(nonce, plain.as_slice()).unwrap();
        payload.extend_from_slice(&ct);
        let out = d
            .decrypt_chunk_payload(&payload, plain.len() as u32)
            .unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn reject_wrong_key_or_tamper() {
        let d = Decryptor::new([1u8; 32]);
        let plain = vec![9u8; 64];
        let mut payload = vec![0u8; NONCE_LEN];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&[1u8; 32]));
        let nonce = Nonce::from_slice(&payload);
        let ct = cipher.encrypt(nonce, plain.as_slice()).unwrap();
        payload.extend_from_slice(&ct);

        // 篡改密文 → 认证失败
        let mut bad = payload.clone();
        bad[NONCE_LEN] ^= 0x01;
        assert!(d.decrypt_chunk_payload(&bad, 64).is_err());
        // 长度不符
        assert!(d.decrypt_chunk_payload(&payload, 128).is_err());
        // 密钥不符
        let d2 = Decryptor::new([2u8; 32]);
        assert!(d2.decrypt_chunk_payload(&payload, 64).is_err());
    }

    #[test]
    fn key_sources() {
        let hex_key = hex::encode([0xABu8; 32]);
        assert!(Decryptor::from_key_hex(&hex_key).is_ok());
        assert!(Decryptor::from_key_hex("abcd").is_err());
        let p = std::env::temp_dir().join("sovvault-test.key");
        std::fs::write(&p, [0x11u8; 32]).unwrap();
        assert!(Decryptor::from_key_file(&p).is_ok());
        std::fs::write(&p, [0x11u8; 16]).unwrap();
        assert!(Decryptor::from_key_file(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }
}
