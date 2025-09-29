/// 声明 `core` 模块，它包含了所有的核心实现。
pub mod core;

/// 将 `core` 模块中的关键公共项重新导出到库的顶层命名空间。
/// 这样外部使用者就可以通过 `aegispass::aegis_pass_generator` 的方式直接调用，
/// 而不是 `aegispass::core::aegis_pass_generator`，让 API 更简洁。
pub use crate::core::{aegis_pass_generator, AegisPassError, Preset};

