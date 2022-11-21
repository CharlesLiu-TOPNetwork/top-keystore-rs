#![allow(non_snake_case)]
mod error;
mod t0_algorithm;
mod t0_type;
mod t8_algorithm;
mod t8_type;
mod top_utils;

pub use error::KeystoreError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use t0_algorithm::{decrypt_T0_keystore, generate_T0_key_with_args};
use t8_algorithm::{decrypt_T8_keystore, generate_T8_key_with_args};

use pyo3::prelude::*;

#[derive(Debug, Deserialize, Serialize)]
struct KeystoreResult {
    keystore_name: String,
    keystore_content: String,
}

#[pyfunction]
fn py_generate_keystore_T0(pk_hex: String, password: String) -> PyResult<String> {
    if let Ok(pk) = hex::decode(pk_hex) {
        Ok(generate_T0_keystore(&pk, &password, None).unwrap_or_else(|e| e.to_string()))
    } else {
        Ok(String::from("must use hex private key without `0x` prefix like \"0000000000000000000000000000000000000000000000000000000000000001\""))
    }
}

#[pyfunction]
fn py_generate_keystore_T8(pk_hex: String, password: String) -> PyResult<String> {
    if let Ok(pk) = hex::decode(pk_hex) {
        Ok(generate_T8_keystore(&pk, &password, None).unwrap_or_else(|e| e.to_string()))
    } else {
        Ok(String::from("must use hex private key without `0x` prefix like \"0000000000000000000000000000000000000000000000000000000000000001\""))
    }
}

#[pyfunction]
fn py_generate_keystore_T0_worker(
    pk_hex: String,
    password: String,
    owner_address: String,
) -> PyResult<String> {
    if let Ok(pk) = hex::decode(pk_hex) {
        Ok(generate_T0_keystore(&pk, &password, Some(owner_address))
            .unwrap_or_else(|e| e.to_string()))
    } else {
        Ok(String::from("must use hex private key without `0x` prefix like \"0000000000000000000000000000000000000000000000000000000000000001\""))
    }
}

#[pyfunction]
fn py_generate_keystore_T8_worker(
    pk_hex: String,
    password: String,
    owner_address: String,
) -> PyResult<String> {
    if let Ok(pk) = hex::decode(pk_hex) {
        Ok(generate_T8_keystore(&pk, &password, Some(owner_address))
            .unwrap_or_else(|e| e.to_string()))
    } else {
        Ok(String::from("must use hex private key without `0x` prefix like \"0000000000000000000000000000000000000000000000000000000000000001\""))
    }
}

#[pyfunction]
fn py_decrypt_T8_keystore(keystore_str: String, password: String) -> PyResult<String> {
    Ok(decrypt_T8_keystore_file(keystore_str, password).unwrap_or_else(|e| e.to_string()))
}

#[pyfunction]
fn py_decrypt_T0_keystore(keystore_str: String, password: String) -> PyResult<String> {
    Ok(decrypt_T0_keystore_file(keystore_str, password).unwrap_or_else(|e| e.to_string()))
}

#[pymodule]
fn top_keystore_rs(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_generate_keystore_T0, m)?)?;
    m.add_function(wrap_pyfunction!(py_generate_keystore_T8, m)?)?;
    m.add_function(wrap_pyfunction!(py_generate_keystore_T0_worker, m)?)?;
    m.add_function(wrap_pyfunction!(py_generate_keystore_T8_worker, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_T8_keystore, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_T0_keystore, m)?)?;
    Ok(())
}

pub fn generate_T0_keystore<PriK, S>(
    pk: PriK,
    password: S,
    is_miner: Option<String>,
) -> Result<String, KeystoreError>
where
    PriK: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    let mut rng = rand::thread_rng();

    const DEFAULT_SALT_SIZE: usize = 32usize;
    const DEFAULT_IV_SIZE: usize = 16usize;
    const DEFAULT_INFO_SIZE: usize = 8usize;

    let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    let mut info = vec![0u8; DEFAULT_INFO_SIZE];

    rng.fill_bytes(iv.as_mut_slice());
    rng.fill_bytes(salt.as_mut_slice());
    rng.fill_bytes(info.as_mut_slice());

    let prikey_base = base64::encode(&pk);

    // println!("base prikey {}", prikey_base);

    let keystore =
        generate_T0_key_with_args(prikey_base, password, info, salt, iv, is_miner.clone())?;

    let keystore_result = KeystoreResult {
        keystore_name: keystore.1.unwrap_or(keystore.0.account_address.to_string()),
        keystore_content: serde_json::to_string(&keystore.0)?,
    };

    let result = serde_json::to_string(&keystore_result)?;

    Ok(result)
}

pub fn generate_T8_keystore<PriK, S>(
    pk: PriK,
    password: S,
    is_miner: Option<String>,
) -> Result<String, KeystoreError>
where
    PriK: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    let mut rng = rand::thread_rng();

    const DEFAULT_SALT_SIZE: usize = 32usize;
    const DEFAULT_IV_SIZE: usize = 16usize;

    let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];

    rng.fill_bytes(iv.as_mut_slice());
    rng.fill_bytes(salt.as_mut_slice());

    let prikey_hex = hex::encode(&pk);

    // println!("hex prikey {}", prikey_hex);

    let keystore = generate_T8_key_with_args(prikey_hex, password, salt, iv, is_miner.clone())?;

    let keystore_result = KeystoreResult {
        keystore_name: keystore.1.unwrap_or(keystore.0.account_address.to_string()),
        keystore_content: serde_json::to_string(&keystore.0)?,
    };

    let result = serde_json::to_string(&keystore_result)?;

    Ok(result)
}

pub fn decrypt_T8_keystore_file(
    keystore: String,
    password: String,
) -> Result<String, KeystoreError> {
    let keystore = serde_json::from_str(&keystore)?;
    decrypt_T8_keystore(keystore, password)
}

pub fn decrypt_T0_keystore_file(
    keystore: String,
    password: String,
) -> Result<String, KeystoreError> {
    // compatible for old `account address`
    let keystore = keystore.replace("account address", "account_address");
    let keystore = serde_json::from_str(&keystore)?;
    decrypt_T0_keystore(keystore, password)
}
