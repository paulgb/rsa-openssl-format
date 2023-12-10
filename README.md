# `rsa-openssl-format`

This is a Rust crate for converting RSA public keys from the `rsa` crate (`rsa::RsaPublicKey`)
to and from the serialized key format used by OpenSSL for `authorized_keys` entries.

## Disclaimer

I couldn’t find an official spec for the encoding format that OpenSSL uses for `authorized_keys`
files. I have tested this on thousands of keys generated by `ssh-keygen` to confirm that it
generates the same output.

## Example

This example shows how to convert an RSA public key from the `rsa` crate to the
format used by OpenSSL for `authorized_keys` files.

```rust
use rsa::{pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}, RsaPublicKey};
use rsa_openssl_format::AuthorizedKeysFormat;

const PEM_KEY: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAxTpMM4DEZE6ohGi/M6JBI99x8QpZ0eOk9Wy1EiEojGiSubbbdO/o
PByrKCgy+eDi0eyn2h9FMkpwqQEhUHiNpbHJLu3dQ4wR9SWLM5Ppm5WVTpBZx7C2
mrNh66mqDmVELYMM1S6VF6GYRGpTK1XOCqnDjSuTpaE8DvntL5bSruyAqfd7848w
CUXObvImjC000lUqYKkPtqjYBxHPK4FbgWhwuZdwwOqg1QyUSlQ74q7YC3WbiK2u
qB069H/PA1rk0wvC6b9b93U/cOA9TYQ9fL8Hv0WsojqHKFUf5zO25BXPaC5eGm/P
IpDHhLcSObVXc5COAZJv3ukYu6a8PHJYlyVrYq78RC/Pe6JFEm+X6Vha4GCsncgE
fdEBx9JvsMFAXDkgc9xL3LfZDyUy+D+O7ld6H3v5upYEbWLyiFIN/DdGaJtl2IVE
ggnQZewCyy9qhdrqheao1PNvmtFm9yPQJ6FrCbs6Gi2il/48NRdX5T1nhcokMdUe
m+sGH+Vv9LyBAgMBAAE=
-----END RSA PUBLIC KEY-----
"#;

const OPENSSL_KEY: &str = "ssh-rsa \
AAAAB3NzaC1yc2EAAAADAQABAAABgQDFOkwzgMRkTqiEaL8zokEj33HxClnR46T\
1bLUSISiMaJK5ttt07+g8HKsoKDL54OLR7KfaH0UySnCpASFQeI2lscku7d1DjB\
H1JYszk+mblZVOkFnHsLaas2HrqaoOZUQtgwzVLpUXoZhEalMrVc4KqcONK5Olo\
TwO+e0vltKu7ICp93vzjzAJRc5u8iaMLTTSVSpgqQ+2qNgHEc8rgVuBaHC5l3DA\
6qDVDJRKVDvirtgLdZuIra6oHTr0f88DWuTTC8Lpv1v3dT9w4D1NhD18vwe/Ray\
iOocoVR/nM7bkFc9oLl4ab88ikMeEtxI5tVdzkI4Bkm/e6Ri7prw8cliXJWtirv\
xEL897okUSb5fpWFrgYKydyAR90QHH0m+wwUBcOSBz3Evct9kPJTL4P47uV3ofe\
/m6lgRtYvKIUg38N0Zom2XYhUSCCdBl7ALLL2qF2uqF5qjU82+a0Wb3I9AnoWsJ\
uzoaLaKX/jw1F1flPWeFyiQx1R6b6wYf5W/0vIE= my-comment";

fn main() {
    // Convert a PEM-format key to OpenSSL format.    
    let key = RsaPublicKey::from_pkcs1_pem(PEM_KEY).unwrap();
    let openssl_key = key.to_openssl("my-comment");

    assert_eq!(OPENSSL_KEY, openssl_key);

    // Convert an OpenSSL-format key to PEM format.
    let (key, comment) = RsaPublicKey::from_openssl(&OPENSSL_KEY).unwrap();
    let pem_key = key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();

    assert_eq!(PEM_KEY, pem_key);
    assert_eq!("my-comment", comment);
}
```
