//! Configuration loading and validation errors.

use std::path::PathBuf;
use thiserror::Error;

/// Configuration loading and validation errors.
///
/// Covers errors in configuration file parsing, validation, and environment
/// variable processing. File paths may be included for debugging purposes.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: PathBuf },

    /// Configuration file is not readable
    #[error("Cannot read configuration file: {path}")]
    FileNotReadable { path: PathBuf },

    /// Configuration file has invalid syntax
    #[error("Invalid configuration syntax in file: {path}")]
    InvalidSyntax { path: PathBuf },

    /// Missing required configuration field
    #[error("Missing required configuration field: {field}")]
    MissingField { field: String },

    /// Invalid value for configuration field
    #[error("Invalid value for field '{field}': {reason}")]
    InvalidValue { field: String, reason: String },

    /// Conflicting configuration options
    #[error("Conflicting configuration: {conflict}")]
    Conflict { conflict: String },

    /// Environment variable parsing error
    #[error("Invalid environment variable: {variable}")]
    InvalidEnvironmentVariable { variable: String },

    /// TOML deserialization error
    #[error("Configuration parsing error: {message}")]
    ParseError { message: String },
}
