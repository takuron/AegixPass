use std::path::PathBuf;
use clap::Parser;
// 从我们自己的库 `aegispass` 中导入所需的函数和结构体。
use aegispass::{aegis_pass_generator, AegisPassError, Preset};

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

    // Parse the JSON preset.
    // 解析 JSON 预设。
    let preset: Preset = serde_json::from_str(&json_content)
        .map_err(|e| AegisPassError::PresetParseError(e.to_string()))?;

    // Call the core function to generate the password.
    // 调用核心函数生成密码。
    let password = aegis_pass_generator(&args.password_source, &args.distinguish_key, &preset)?;

    Ok(password)
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