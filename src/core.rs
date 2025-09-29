// --- 导入依赖 ---
// Serde 库，用于在 Rust 数据结构和 JSON 格式之间进行序列化和反序列化。
use serde::Deserialize;
// SHA-2 哈希算法库，一个广泛使用的标准哈希函数。
use sha2::{Digest, Sha256};
// 随机数生成相关库。prelude 导入了最常用的 traits，如 Rng 和 SeedableRng。
use rand::prelude::*;
// ChaCha20 是一个高性能的、可从种子（seed）创建的确定性随机数生成器 (RNG)。
use rand_chacha::ChaCha20Rng;
// thiserror 库，可以方便地为自定义错误类型派生标准的 Error trait。
use thiserror::Error;

// --- 1. 定义 AegisPass 的 JSON 数据结构和相关枚举 ---

/// 定义密码生成所使用的哈希算法。
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

/// 定义密码生成所使用的确定性随机数生成器 (RNG) 算法。
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum RngAlgorithm {
    ChaCha20,
}

/// 定义密码洗牌所使用的算法。
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ShuffleAlgorithm {
    FisherYates, // Fisher-Yates 是标准库 `slice::shuffle` 使用的算法。
}

/// 定义所有可能发生的错误，利用 thiserror 使错误信息更友好。
#[derive(Error, Debug, PartialEq)]
pub enum AegisPassError {
    #[error("主密码 (passwordSource) 和区分密钥 (distinguishKey) 不能为空。")]
    InputEmpty,
    #[error("密码长度 ({0}) 太短，无法保证包含所有 {1} 个字符集分组的字符。")]
    LengthTooShort(usize, usize),
    #[error("所有字符集分组都必须包含至少一个字符。")]
    EmptyCharset,
    #[error("解析预设JSON失败: {0}")]
    PresetParseError(String),
    #[error("字符集分组数量 ({0}) 过多，此算法最多支持 {1} 个分组。")]
    TooManyCharsetGroups(usize, usize),
}

/// 定义 AegisPass 密码生成预设的完整结构体。
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

// --- 2. 核心密码生成函数 ---

/// 主函数，根据给定的输入和预设配置，生成最终的密码。
pub fn aegis_pass_generator(
    password_source: &str,
    distinguish_key: &str,
    preset: &Preset,
) -> Result<String, AegisPassError> {
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

    // --- (阶段 B) 生成核心种子 ---
    let master_seed = generate_master_seed(password_source, distinguish_key, preset);

    // --- (阶段 A) 输入验证 (补充) ---
    const CHUNK_SIZE: usize = 4; // 为每个字符集分配的种子字节数
    let max_groups: usize = master_seed.len() / CHUNK_SIZE;
    if preset.charsets.len() > max_groups {
        return Err(AegisPassError::TooManyCharsetGroups(
            preset.charsets.len(),
            max_groups,
        ));
    }

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

    // --- (阶段 D) 填充密码剩余长度 ---
    let remaining_len = preset.length - final_password_chars.len();
    if remaining_len > 0 {
        let combined_charset_str: String = preset.charsets.join("");
        let mut combined_charset: Vec<char> = combined_charset_str.chars().collect();
        let mut rng = create_rng_from_seed(master_seed, &preset.rng_algorithm);
        combined_charset.shuffle(&mut rng);
        for i in 0..remaining_len {
            final_password_chars.push(combined_charset[i % combined_charset.len()]);
        }
    }

    // --- (阶段 E) 最终整体洗牌 ---
    let mut rng = create_rng_from_seed(master_seed, &preset.rng_algorithm);
    final_password_chars.shuffle(&mut rng);

    // --- (阶段 F) 组合并返回结果 ---
    Ok(final_password_chars.into_iter().collect())
}

/// 根据所有输入信息，生成一个32字节的确定性主种子（Master Seed）。
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
    }
}

/// 根据主种子和预设算法，创建一个可用的确定性随机数生成器 (RNG)。
fn create_rng_from_seed(seed: [u8; 32], rng_algorithm: &RngAlgorithm) -> impl Rng + SeedableRng {
    match rng_algorithm {
        RngAlgorithm::ChaCha20 => ChaCha20Rng::from_seed(seed),
    }
}

// --- 单元测试模块 ---
#[cfg(test)]
mod tests {
    use super::*;

    fn load_default_preset() -> Preset {
        let json_preset = r#"
        {
          "name": "AegisPass Default",
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
        serde_json::from_str(json_preset).expect("测试中的预设JSON无效")
    }

    #[test]
    fn test_determinism() {
        let preset = load_default_preset();
        let pass1 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        let pass2 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        assert_eq!(pass1, pass2, "相同的输入应该产生相同的密码");
    }

    #[test]
    fn test_uniqueness() {
        let preset = load_default_preset();
        let pass1 = aegis_pass_generator("MySecretPassword123!", "example.com", &preset).unwrap();
        let pass2 = aegis_pass_generator("MySecretPassword123!", "anothersite.org", &preset).unwrap();
        assert_ne!(pass1, pass2, "不同的密钥应该产生不同的密码");
    }

    #[test]
    fn test_all_charsets_are_used() {
        let preset = load_default_preset();
        let password = aegis_pass_generator("a-very-long-and-random-password", "a-very-long-key", &preset).unwrap();
        for charset in &preset.charsets {
            assert!(charset.chars().any(|c| password.contains(c)), "密码 '{}' 中必须包含来自字符集 '{}' 的字符", password, charset);
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
}