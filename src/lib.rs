#![doc = include_str!("../README.md")]

use length_encoded::{LengthEncodedReader, LengthEncodedWriter};
use num_bigint_dig::BigUint;
use rsa::{RsaPublicKey, traits::PublicKeyParts};

mod length_encoded;

const SSH_RSA: &str = "ssh-rsa";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RsaPubKeyError {
    #[error("Invalid base64.")]
    InvalidBase64(#[from] data_encoding::DecodeError),

    #[error("Unsupported key type {0} (only RSA keys are supported).")]
    UnsupportedKeyType(String),

    #[error("Length is invalid (not enough bytes).")]
    InvalidLength,

    #[error("Malformed (expected `ssh-rsa <base64-encoded data> <comment>`)")]
    Malformed,

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::errors::Error),
}

pub trait AuthorizedKeysFormat {
    fn to_openssl(&self, comment: &str) -> String;
    fn from_openssl(openssl_pubkey: &str) -> Result<(Self, String), RsaPubKeyError>
    where
        Self: Sized;
}

pub fn to_base64(key: &RsaPublicKey) -> String {
    let mut writer = LengthEncodedWriter::new();

    writer.write_length_encoded(SSH_RSA.as_bytes()).unwrap();
    writer.write_length_encoded(&key.e().to_bytes_be()).unwrap();
    let mut modulus_bytes = Vec::with_capacity(key.n().bits() as usize + 1);
    modulus_bytes.push(0);
    modulus_bytes.extend(key.n().to_bytes_be());
    writer.write_length_encoded(&modulus_bytes).unwrap();

    let buf = writer.take();
    data_encoding::BASE64.encode(&buf)
}

pub fn from_base64(base64: &str) -> Result<RsaPublicKey, RsaPubKeyError> {
    let buf = data_encoding::BASE64.decode(base64.as_bytes())?;
    let mut reader = LengthEncodedReader::new(buf);

    let key_type = reader
        .read_length_encoded()
        .map_err(|_| RsaPubKeyError::InvalidLength)?;
    let key_type = std::str::from_utf8(&key_type)
        .map_err(|_| RsaPubKeyError::UnsupportedKeyType(format!("{:?}", key_type)))?;
    if key_type != SSH_RSA {
        return Err(RsaPubKeyError::UnsupportedKeyType(key_type.to_string()));
    }

    let e = reader
        .read_length_encoded()
        .map_err(|_| RsaPubKeyError::InvalidLength)?;
    let e = BigUint::from_bytes_be(&e);

    let n = reader
        .read_length_encoded()
        .map_err(|_| RsaPubKeyError::InvalidLength)?;
    let n = BigUint::from_bytes_be(&n);

    Ok(RsaPublicKey::new(n, e)?)
}

impl AuthorizedKeysFormat for RsaPublicKey {
    fn to_openssl(&self, comment: &str) -> String {
        format!("{} {} {}", SSH_RSA, to_base64(self), comment)
    }

    fn from_openssl(openssl_pubkey: &str) -> Result<(Self, String), RsaPubKeyError> {
        let Some((key_type, rest)) = openssl_pubkey.split_once(' ') else {
            return Err(RsaPubKeyError::Malformed);
        };

        if key_type != SSH_RSA {
            return Err(RsaPubKeyError::UnsupportedKeyType(key_type.to_string()));
        }

        let (key, comment) = if let Some((key, comment)) = rest.split_once(' ') {
            (key, Some(comment.to_string()))
        } else {
            (rest, None)
        };

        let pubkey = from_base64(key)?;

        Ok((pubkey, comment.unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trips() {
        let test_keys = include_str!("../test_keys.txt");
        for line in test_keys.lines() {
            let line = line.trim();

            let (key, comment) = RsaPublicKey::from_openssl(line).unwrap();
            let line_with_roundtrip = key.to_openssl(&comment);

            let (key_after_roundtrip, comment_after_roundtrip) =
                RsaPublicKey::from_openssl(&line_with_roundtrip).unwrap();
            assert_eq!(key, key_after_roundtrip);
            assert_eq!(comment, comment_after_roundtrip);

            assert_eq!(line, line_with_roundtrip);
        }
    }
}
