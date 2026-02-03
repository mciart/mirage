//! Certificate loading utilities for the Mirage VPN system.
//!
//! This module provides functions to load X.509 certificates and private keys
//! from files, using the boring (BoringSSL) library.

use crate::error::{CertificateError, Result};
use boring::pkey::{PKey, Private};
use boring::x509::X509;
use std::fs;
use std::path::Path;

/// Loads an X.509 certificate from a PEM file.
///
/// ### Arguments
/// - `path` - Path to the file containing the PEM-encoded certificate.
///
/// ### Returns
/// - `X509` - The loaded certificate.
pub fn load_certificate_from_file(path: &Path) -> Result<X509> {
    let pem_data = fs::read(path).map_err(|_| CertificateError::LoadFailed {
        path: path.to_path_buf(),
    })?;

    X509::from_pem(&pem_data).map_err(|_| {
        CertificateError::LoadFailed {
            path: path.to_path_buf(),
        }
        .into()
    })
}

/// Loads an X.509 certificate from PEM-encoded string.
///
/// ### Arguments
/// - `pem_data` - PEM-encoded certificate data as a string.
///
/// ### Returns
/// - `X509` - The loaded certificate.
pub fn load_certificate_from_pem(pem_data: &str) -> Result<X509> {
    X509::from_pem(pem_data.as_bytes()).map_err(|_| CertificateError::UnsupportedFormat.into())
}

/// Loads a private key from a PEM file.
///
/// ### Arguments
/// - `path` - Path to the file containing the PEM-encoded private key.
///
/// ### Returns
/// - `PKey<Private>` - The loaded private key.
pub fn load_private_key_from_file(path: &Path) -> Result<PKey<Private>> {
    let pem_data = fs::read(path).map_err(|_| CertificateError::PrivateKeyLoadFailed {
        path: path.to_path_buf(),
    })?;

    PKey::private_key_from_pem(&pem_data).map_err(|_| {
        CertificateError::PrivateKeyLoadFailed {
            path: path.to_path_buf(),
        }
        .into()
    })
}

/// Loads a private key from PEM-encoded string.
///
/// ### Arguments
/// - `pem_data` - PEM-encoded private key data as a string.
///
/// ### Returns
/// - `PKey<Private>` - The loaded private key.
pub fn load_private_key_from_pem(pem_data: &str) -> Result<PKey<Private>> {
    PKey::private_key_from_pem(pem_data.as_bytes())
        .map_err(|_| CertificateError::UnsupportedFormat.into())
}
