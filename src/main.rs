use std::path::PathBuf;
use clap::Parser;
// 从我们自己的库 `aegispass` 中导入所需的函数和结构体。
use aegispass::{aegis_pass_generator, AegisPassError, Preset};

/// 使用 clap 定义命令行参数的结构体。
#[derive(Parser, Debug)]
#[command(
    name = "aegispass",
    version = "1.0",
    author = "AegisPass Developer",
    about = "一个确定性的密码生成器。",
    long_about = "根据主密码、区分密钥和配置文件，确定性地生成高强度密码。"
)]
struct CliArgs {
    /// 指定预设的JSON配置文件路径。
    #[arg(short, long, value_name = "FILE_PATH")]
    config: Option<PathBuf>,

    /// 你的主密码，只有你自己知道。
    password_source: String,

    /// 用于区分不同网站或应用的密钥 (例如 'example.com')。
    distinguish_key: String,
}

/// 运行程序并处理主要逻辑，返回 Result 类型以便于错误处理。
fn run() -> Result<String, Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    // 确定配置文件的路径
    let config_path = match args.config {
        // 如果用户通过 -c 或 --config 提供了路径，则使用该路径
        Some(path) => path,
        // 否则，构建一个指向可执行文件同目录下 "default.json" 的路径
        None => {
            let mut path = std::env::current_exe()?;
            path.pop(); // 移除可执行文件名
            path.push("default.json"); // 添加默认配置文件名
            path
        }
    };

    // 读取配置文件内容
    let json_content = std::fs::read_to_string(&config_path).map_err(|e| {
        format!(
            "无法读取配置文件 '{}': {}",
            config_path.display(),
            e
        )
    })?;

    // 解析 JSON 预设
    let preset: Preset = serde_json::from_str(&json_content)
        .map_err(|e| AegisPassError::PresetParseError(e.to_string()))?;

    // 调用核心函数生成密码
    let password = aegis_pass_generator(&args.password_source, &args.distinguish_key, &preset)?;

    Ok(password)
}

/// 程序入口
fn main() {
    // 执行 run 函数并处理可能发生的任何错误
    match run() {
        Ok(password) => {
            // 成功时，将生成的密码打印到标准输出
            println!("{}", password);
        }
        Err(e) => {
            // 失败时，将错误信息打印到标准错误输出，并以非零状态码退出
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
    }
}
