// --- Dependencies ---
// --- 导入依赖 ---
// Serde library for serializing and deserializing Rust data structures to and from JSON.
// Serde 库，用于在 Rust 数据结构和 JSON 格式之间进行序列化和反序列化。
use serde::Deserialize;
// SHA-2 hashing library, a widely used standard hash function.
// SHA-2 哈希算法库，一个广泛使用的标准哈希函数。
use sha2::{Digest, Sha256};
// Random number generation libraries. The prelude imports the most common traits like Rng and SeedableRng.
// 随机数生成相关库。prelude 导入了最常用的 traits，如 Rng 和 SeedableRng。
use rand::prelude::*;
// ChaCha20 is a high-performance, deterministic random number generator (RNG) that can be created from a seed.
// ChaCha20 是一个高性能的、可从种子（seed）创建的确定性随机数生成器 (RNG)。
use rand_chacha::ChaCha20Rng;
use rand_hc::Hc128Rng;
use sha3::Sha3_256;
// thiserror library to easily derive the standard Error trait for custom error types.
// thiserror 库，可以方便地为自定义错误类型派生标准的 Error trait。
use thiserror::Error;

// --- 1. Define AegisPass JSON data structures and related enums ---
// --- 1. 定义 AegisPass 的 JSON 数据结构和相关枚举 ---

/// Defines the hash algorithm used for password generation.
// 定义密码生成所使用的哈希算法。
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
    Sha3_256,
}

/// Defines the deterministic random number generator (RNG) algorithm used for password generation.
// 定义密码生成所使用的确定性随机数生成器 (RNG) 算法。
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum RngAlgorithm {
    ChaCha20,
    Hc128
}

/// Defines the algorithm used for shuffling the password characters.
// 定义密码洗牌所使用的算法。
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ShuffleAlgorithm {
    FisherYates, // Fisher-Yates is the algorithm used by the standard library's `slice::shuffle`.
    // Fisher-Yates 是标准库 `slice::shuffle` 使用的算法。
}

/// Defines all possible errors that can occur, using thiserror for more user-friendly error messages.
// 定义所有可能发生的错误，利用 thiserror 使错误信息更友好。
#[derive(Error, Debug, PartialEq)]
pub enum AegisPassError {
    #[error("Master password (passwordSource) and distinguish key (distinguishKey) cannot be empty.")]
    InputEmpty,
    #[error("Password length ({0}) is too short to guarantee inclusion of characters from all {1} charset groups.")]
    LengthTooShort(usize, usize),
    #[error("All charset groups must contain at least one character.")]
    EmptyCharset,
    #[error("Failed to parse the preset JSON: {0}")]
    PresetParseError(String),
    #[error("The number of charset groups ({0}) is too large; this algorithm supports a maximum of {1} groups.")]
    TooManyCharsetGroups(usize, usize),
}

/// Defines the complete structure for an AegisPass password generation preset.
// 定义 AegisPass 密码生成预设的完整结构体。
#[derive(Debug, Deserialize, PartialEq)]
pub struct Preset {
    pub name: String,
    pub version: u32,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: HashAlgorithm,
    #[serde(rename = "rngAlgorithm")]
    pub rng_algorithm: RngAlgorithm,
    #[serde(rename = "shuffleAlgorithm")]
    pub shuffle_algorithm: ShuffleAlgorithm,
    pub length: usize,
    #[serde(rename = "platformId")]
    pub platform_id: String,
    pub charsets: Vec<String>,
}

// --- 2. Core Password Generation Function ---
// --- 2. 核心密码生成函数 ---

/// The main function that generates the final password based on the given inputs and preset configuration.
// 主函数，根据给定的输入和预设配置，生成最终的密码。
pub fn aegis_pass_generator(
    password_source: &str,
    distinguish_key: &str,
    preset: &Preset,
) -> Result<String, AegisPassError> {
    // --- (Stage A) Input Validation (Partial) ---
    // --- (阶段 A) 输入验证 (部分) ---
    if password_source.is_empty() || distinguish_key.is_empty() {
        return Err(AegisPassError::InputEmpty);
    }
    if preset.length < preset.charsets.len() {
        return Err(AegisPassError::LengthTooShort(
            preset.length,
            preset.charsets.len(),
        ));
    }
    if preset.charsets.iter().any(|cs| cs.is_empty()) {
        return Err(AegisPassError::EmptyCharset);
    }

    // --- (Stage B) Generate the Master Seed ---
    // --- (阶段 B) 生成核心种子 ---
    let master_seed = generate_master_seed(password_source, distinguish_key, preset);

    // --- (Stage A) Input Validation (Supplemental) ---
    // --- (阶段 A) 输入验证 (补充) ---
    const CHUNK_SIZE: usize = 4; // Number of seed bytes allocated for each charset.
    // 为每个字符集分配的种子字节数
    let max_groups: usize = master_seed.len() / CHUNK_SIZE;
    if preset.charsets.len() > max_groups {
        return Err(AegisPassError::TooManyCharsetGroups(
            preset.charsets.len(),
            max_groups,
        ));
    }

    // --- (Stage C) Ensure at least one character from each charset is included (Enhanced Security Version) ---
    // --- (阶段 C) 保证每个字符集至少出现一次 (安全增强版) ---
    let mut final_password_chars: Vec<char> = Vec::with_capacity(preset.length);
    for (i, charset_group) in preset.charsets.iter().enumerate() {
        let start_index = i * CHUNK_SIZE;
        let end_index = start_index + CHUNK_SIZE;
        let chunk: [u8; CHUNK_SIZE] = master_seed[start_index..end_index]
            .try_into()
            .expect("Chunk size is guaranteed to be valid");
        let index_seed = u32::from_le_bytes(chunk);
        let char_index = (index_seed as u64 % charset_group.len() as u64) as usize;
        let chars: Vec<char> = charset_group.chars().collect();
        final_password_chars.push(chars[char_index]);
    }

    // 从种子创建 RNG 实例
    let mut rng = create_rng_from_seed(master_seed, &preset.rng_algorithm);

    // --- (阶段 D) 填充密码剩余长度 ---
    let remaining_len = preset.length - final_password_chars.len();
    if remaining_len > 0 {
        let combined_charset_str: String = preset.charsets.join("");
        let combined_charset: Vec<char> = combined_charset_str.chars().collect();
        let combined_len = combined_charset.len() as u32;

        // --- 最终优化：不再洗牌，而是循环随机抽样 ---
        for _ in 0..remaining_len {
            let j = secure_random_range_u32(&mut *rng, combined_len) as usize;
            final_password_chars.push(combined_charset[j]);
        }
    }

    // --- (阶段 E) 最终整体洗牌 ---
    // --- 关键优化：同样使用 u32 版本的洗牌逻辑 ---
    for i in (1..final_password_chars.len()).rev() {
        let j = secure_random_range_u32(&mut *rng, (i + 1) as u32) as usize;
        final_password_chars.swap(i, j);
    }

    // --- (阶段 F) 组合并返回结果 ---
    Ok(final_password_chars.into_iter().collect())
}

/// Generates a 32-byte deterministic master seed from all input information.
// 根据所有输入信息，生成一个32字节的确定性主种子（Master Seed）。
fn generate_master_seed(
    password_source: &str,
    distinguish_key: &str,
    preset: &Preset,
) -> [u8; 32] {
    let input_data = format!(
        "AegisPass_V{}:{}:{}:{}:{}:{}",
        preset.version,
        preset.platform_id,
        preset.length,
        password_source,
        distinguish_key,
        serde_json::to_string(&preset.charsets).unwrap_or_default()
    );
    match preset.hash_algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(input_data.as_bytes()).into(),
        HashAlgorithm::Blake3 => blake3::hash(input_data.as_bytes()).into(),
        HashAlgorithm::Sha3_256 => Sha3_256::digest(input_data.as_bytes()).into(),
    }
}

/// Creates a usable deterministic random number generator (RNG) from the master seed and preset algorithm.
// 根据主种子和预设算法，创建一个可用的确定性随机数生成器 (RNG)。
fn create_rng_from_seed(seed: [u8; 32], rng_algorithm: &RngAlgorithm) -> Box<dyn RngCore> {
    match rng_algorithm {
        RngAlgorithm::ChaCha20 => Box::new(ChaCha20Rng::from_seed(seed)),
        RngAlgorithm::Hc128 => Box::new(Hc128Rng::from_seed(seed)),
    }
}

// --- 辅助函数：一个基于 u32 的、清晰、可移植的无偏范围生成器 ---
fn secure_random_range_u32(rng: &mut dyn RngCore, max: u32) -> u32 {
    let range = max;
    let zone = u32::MAX.wrapping_sub(u32::MAX.wrapping_rem(range));

    loop {
        let v = rng.next_u32();
        if v < zone {
            return v % range;
        }
    }
}

// --- Unit Test Module ---
// --- 单元测试模块 ---
#[cfg(test)]
mod tests {
    use super::*;

    fn load_default_preset() -> Preset {
        let json_preset = r#"
        {
          "name": "AegisPass - Default",
          "version": 1,
          "hashAlgorithm": "sha256",
          "rngAlgorithm": "chaCha20",
          "shuffleAlgorithm": "fisherYates",
          "length": 16,
          "platformId": "aegispass.takuron.com",
          "charsets": [
            "0123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "!@#$%^&*()_+-="
          ]
        }
        "#;
        serde_json::from_str(json_preset).expect("The preset JSON in the test is invalid")
    }

    fn load_sha3_preset() -> Preset {
        let json_preset = r#"
        {
          "name": "AegisPass - Sha3Hc128",
          "version": 1,
          "hashAlgorithm": "sha3",
          "rngAlgorithm": "hc128",
          "shuffleAlgorithm": "fisherYates",
          "length": 16,
          "platformId": "aegispass.takuron.com",
          "charsets": [
            "0123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "!@#$%^&*()_+-="
          ]
        }
        "#;
        serde_json::from_str(json_preset).expect("The preset JSON in the test is invalid")
    }

    #[test]
    fn test_determinism() {
        let preset = load_default_preset();
        let pass1 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        let pass2 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        assert_eq!(pass1, pass2, "The same input should produce the same password");
    }

    #[test]
    fn test_uniqueness() {
        let preset = load_default_preset();
        let pass1 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        let pass2 = aegis_pass_generator("MySecretPassword123!", "anothersite.org", &preset).unwrap();
        assert_ne!(pass1, pass2, "Different keys should produce different passwords");
    }

    #[test]
    fn test_all_charsets_are_used() {
        let preset = load_default_preset();
        let password = aegis_pass_generator("a-very-long-and-random-password", "a-very-long-key", &preset).unwrap();
        for charset in &preset.charsets {
            assert!(charset.chars().any(|c| password.contains(c)), "Password '{}' must contain characters from charset '{}'", password, charset);
        }
    }

    #[test]
    fn test_error_on_length_too_short() {
        let mut preset = load_default_preset();
        preset.length = 3;
        let result = aegis_pass_generator("password", "example.com", &preset);
        assert_eq!(result, Err(AegisPassError::LengthTooShort(3, 4)));
    }

    #[test]
    fn test_error_on_too_many_groups() {
        let mut preset = load_default_preset();
        preset.charsets = vec![
            "1".to_string(), "2".to_string(), "3".to_string(),
            "4".to_string(), "5".to_string(), "6".to_string(),
            "7".to_string(), "8".to_string(), "9".to_string(),
        ];
        preset.length = 10;
        let result = aegis_pass_generator("password", "example.com", &preset);
        assert_eq!(result, Err(AegisPassError::TooManyCharsetGroups(9, 8)));
    }

    #[test]
    fn test_determinism_sha3() {
        let preset = load_sha3_preset();
        let pass1 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        let pass2 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        assert_eq!(pass1, pass2, "The same input should produce the same password");
    }
}