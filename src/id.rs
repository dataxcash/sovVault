//! IDX 报文物理定位符（司法溯源唯一基因）。
//! IDX(u64) = (FILE_ID:u32) << 32 | (OFFSET:u32)，大端存 LMDB。
//! 硬不变量：单文件 ≤ 4GB；OFFSET = 记录起始字节偏移。

/// 单文件字节上限（< 4GB，OFFSET 域为 u32 天然约束）。
pub const MAX_FILE_SIZE: u64 = u32::MAX as u64;

/// 打包 IDX。
#[inline]
pub fn encode(file_id: u32, offset: u32) -> u64 {
    ((file_id as u64) << 32) | (offset as u64)
}

/// 拆解 IDX。
#[inline]
pub fn decode(idx: u64) -> (u32, u32) {
    ((idx >> 32) as u32, idx as u32)
}

/// IDX 大端字节（8 字节，作 LMDB 键）。
#[inline]
pub fn to_bytes(idx: u64) -> [u8; 8] {
    idx.to_be_bytes()
}

/// 从大端字节还原 IDX。
#[inline]
pub fn from_bytes(b: &[u8]) -> Option<u64> {
    if b.len() != 8 {
        return None;
    }
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idx_roundtrip() {
        for (fid, off) in [
            (0u32, 0u32),
            (1, 64),
            (0xDEAD_BEEF, 0x1234_5678),
            (u32::MAX, u32::MAX), // 4GB 边界不变量
        ] {
            let idx = encode(fid, off);
            assert_eq!(decode(idx), (fid, off));
            assert_eq!(from_bytes(&to_bytes(idx)), Some(idx));
        }
    }

    #[test]
    fn idx_must_be_4gb_bounded() {
        // 任意合法 IDX，OFFSET 域必须 ≤ u32::MAX（单文件 4GB 硬约束）。
        let idx = encode(7, u32::MAX);
        assert_eq!(decode(idx).1, u32::MAX);
        assert_eq!(idx >> 32, 7);
    }

    #[test]
    fn idx_bytes_len_checked() {
        assert!(from_bytes(&[0u8; 7]).is_none());
        assert!(from_bytes(&[0u8; 9]).is_none());
    }
}
