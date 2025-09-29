# AegisPass

![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL--2.1-blue.svg)
![Language: Rust](https://img.shields.io/badge/language-Rust-orange.svg)

[English](#english) | [中文](#中文)

---

## English

### AegisPass: A Deterministic Password Generator

AegisPass is a command-line tool that deterministically generates high-strength passwords based on a master password, a distinguishing key, and a configuration profile. This means for the same set of inputs, you will always get the same password, eliminating the need to store them.

### Features

-   **Deterministic**: Always generates the same password from the same inputs.
-   **Secure**: Your master password is never stored. It uses strong cryptographic hash functions (SHA-256, Blake3) and a cryptographically secure pseudo-random number generator (ChaCha20).
-   **Customizable**: Easily define password length, character sets, and algorithms using a JSON configuration file.
-   **Guaranteed Complexity**: Ensures that at least one character from each specified character set is included in the final password.

### Usage

You can run the program from your terminal using the following command structure:

```bash
aegispass <YOUR_MASTER_PASSWORD> <YOUR_DISTINGUISHING_KEY>
```

-   `<YOUR_MASTER_PASSWORD>`: Your secret master password that only you know.
-   `<YOUR_DISTINGUISHING_KEY>`: A key to differentiate passwords, such as a domain name (e.g., `example.com`) or an app name.

#### Example

```bash
aegispass "MySecretPassword123!" "example.com"
```

This will output a deterministically generated password to your console.

#### Using a Custom Configuration

By default, AegisPass looks for a `default.json` file in the same directory as the executable. You can specify a different configuration file using the `-c` or `--config` flag:

```bash
aegispass --config /path/to/my_preset.json "MySecretPassword123!" "example.com"
```

### Configuration File

The password generation process is controlled by a JSON preset file. Here is the default configuration (`default.json`):

```json
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
```

-   `length`: The total length of the generated password.
-   `charsets`: An array of character groups. The generator guarantees the final password includes at least one character from each group.
-   `hashAlgorithm`, `rngAlgorithm`, `shuffleAlgorithm`: The cryptographic primitives used in the generation process.

### Building from Source

1.  **Install Rust**: If you don't have Rust, install it from [rust-lang.org](https://www.rust-lang.org/).
2.  **Clone the Repository**:
    ```bash
    git clone <repository_url>
    cd aegispass
    ```
3.  **Build the Project**:
    ```bash
    cargo build --release
    ```
4.  **Run**: The executable will be located at `target/release/aegispass`.

### License

This project is licensed under the **GNU Lesser General Public License v2.1**. See the `LICENSE` file for details.

---

## 中文

### AegisPass：一个确定性的密码生成器

AegisPass 是一个命令行工具，它能根据一个主密码、一个区分密钥和一个配置文件，确定性地生成高强度密码。这意味着对于同一组输入，你永远会得到相同的密码，从而无需存储它们。

### 功能特性

-   **确定性**: 对于相同的输入，总是生成相同的密码。
-   **安全**: 你的主密码永远不会被存储。它使用了强大的加密哈希函数（SHA-256、Blake3）和加密安全的伪随机数生成器（ChaCha20）。
-   **可定制**: 通过一个 JSON 配置文件，轻松定义密码长度、使用的字符集和算法。
-   **复杂度保证**: 算法确保最终生成的密码中，至少包含一个来自每个指定字符集的字符。

### 如何使用

你可以在终端中通过以下命令结构来运行本程序：

```bash
aegispass <你的主密码> <你的区分密钥>
```

-   `<你的主密码>`: 只有你自己知道的秘密主密码。
-   `<你的区分密钥>`: 一个用于区分不同密码的密钥，例如网站域名 (`example.com`) 或应用名称。

#### 使用示例

```bash
aegispass "MySecretPassword123!" "example.com"
```

这会在你的控制台确定性地生成并输出一个密码。

#### 使用自定义配置

默认情况下，AegisPass 会在可执行文件所在的目录查找名为 `default.json` 的配置文件。你可以通过 `-c` 或 `--config` 参数来指定一个不同的配置文件：

```bash
aegispass --config /path/to/my_preset.json "MySecretPassword123!" "example.com"
```

### 配置文件

密码生成过程由一个 JSON 预设文件控制。以下是默认的配置 (`default.json`)：

```json
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
```

-   `length`: 生成密码的总长度。
-   `charsets`: 一个字符集分组的数组。生成器会确保最终密码中至少包含来自每个分组的一个字符。
-   `hashAlgorithm`, `rngAlgorithm`, `shuffleAlgorithm`: 在生成过程中使用的加密算法。

### 从源码构建

1.  **安装 Rust**: 如果你还没有安装 Rust，请从 [rust-lang.org](https://www.rust-lang.org/) 安装。
2.  **克隆仓库**:
    ```bash
    git clone <repository_url>
    cd aegispass
    ```
3.  **构建项目**:
    ```bash
    cargo build --release
    ```
    此命令会编译一个用于发布的、经过优化的可执行文件。
4.  **运行**: 生成的可执行文件位于 `target/release/aegispass`。

### 许可证

本项目采用 **GNU Lesser General Public License v2.1** 许可证。详情请参阅 `LICENSE` 文件。