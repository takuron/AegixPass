use std::path::PathBuf;
use clap::Parser;
use serde_json::Value;
// 从我们自己的库 `aegixpass` 中导入所需的函数和结构体。
use aegixpass::{aegixpass_generator, AegixPassError, Preset};

/// 使用 clap 定义命令行参数的结构体。
#[derive(Parser, Debug)]
struct CliArgs {
    /// Path to the preset JSON configuration file.
    // 指定预设的JSON配置文件路径。
    #[arg(short, long, value_name = "FILE_PATH")]
    config: Option<PathBuf>,

    /// Your master password, known only to you.
    // 你的主密码，只有你自己知道。
    password_source: String,

    /// A key to distinguish between different websites or applications (e.g., 'example.com').
    // 用于区分不同网站或应用的密钥 (例如 'example.com')。
    distinguish_key: String,
}

/// Run the program and handle the main logic, returning a Result for error handling.
// 运行程序并处理主要逻辑，返回 Result 类型以便于错误处理。
fn run() -> Result<String, Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    // Determine the path of the configuration file.
    // 确定配置文件的路径。
    let config_path = match args.config {
        // If the user provides a path with -c or --config, use it.
        // 如果用户通过 -c 或 --config 提供了路径，则使用该路径。
        Some(path) => path,
        // Otherwise, construct a path to "default.json" in the same directory as the executable.
        // 否则，构建一个指向可执行文件同目录下 "default.json" 的路径。
        None => {
            let mut path = std::env::current_exe()?;
            path.pop(); // Remove the executable's filename. / 移除可执行文件名。
            path.push("default.json"); // Add the default config filename. / 添加默认配置文件名。
            path
        }
    };

    // Read the content of the configuration file.
    // 读取配置文件内容。
    let json_content = std::fs::read_to_string(&config_path).map_err(|e| {
        format!(
            "Could not read config file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    // --- 版本检查逻辑 ---
    // 1. 先将 JSON 字符串解析为一个通用的 Value 类型。
    let json_value: Value = serde_json::from_str(&json_content)
        .map_err(|e| AegixPassError::PresetParseError(e.to_string()))?;

    // 2. 检查 version 字段。
    match json_value.get("version").and_then(|v| v.as_u64()) {
        Some(1) => {
            // 版本正确，现在可以安全地将 Value 反序列化为 Preset 结构体。
            // 这样做比重新从字符串解析更高效。
            let preset: Preset = serde_json::from_value(json_value)
                .map_err(|e| AegixPassError::PresetParseError(e.to_string()))?;

            // 调用核心函数生成密码。
            let password = aegixpass_generator(&args.password_source, &args.distinguish_key, &preset)?;
            Ok(password)
        }
        Some(version) => {
            // 如果版本号存在但不是 1，则返回错误。
            Err(format!(
                "Unsupported config file version: {}. This program only supports version 1.",
                version
            ).into())
        }
        None => {
            // 如果 "version" 字段不存在或其类型不是一个有效的数字。
            Err("Config file is missing a valid 'version' field.".into())
        }
    }
}

/// Program entry point.
// 程序入口。
fn main() {
    // Execute the run function and handle any potential errors.
    // 执行 run 函数并处理可能发生的任何错误。
    match run() {
        Ok(password) => {
            // On success, print the generated password to standard output.
            // 成功时，将生成的密码打印到标准输出。
            println!("{}", password);
        }
        Err(e) => {
            // On failure, print the error message to standard error and exit with a non-zero status code.
            // 失败时，将错误信息打印到标准错误输出，并以非零状态码退出。
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}