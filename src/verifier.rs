use std::fmt::Write;

use rust_sdk_4mica::{BLSCert, PaymentGuaranteeClaims};

pub trait CertificateValidator: Send + Sync {
    fn verify_certificate(&self, cert: &BLSCert) -> Result<PaymentGuaranteeClaims, String>;
}

pub struct CertificateVerifier {
    operator_public_key: [u8; 48],
    guarantee_domain: Option<[u8; 32]>,
}

impl CertificateVerifier {
    pub fn new(operator_public_key: [u8; 48], guarantee_domain: Option<[u8; 32]>) -> Self {
        Self {
            operator_public_key,
            guarantee_domain,
        }
    }
}

impl CertificateValidator for CertificateVerifier {
    fn verify_certificate(&self, cert: &BLSCert) -> Result<PaymentGuaranteeClaims, String> {
        let is_valid = cert
            .verify(&self.operator_public_key)
            .map_err(|err| err.to_string())?;

        if !is_valid {
            return Err("certificate signature mismatch".into());
        }

        let claims_bytes = cert.claims_bytes().map_err(|err| err.to_string())?;
        let claims = PaymentGuaranteeClaims::try_from(claims_bytes.as_slice())
            .map_err(|err| err.to_string())?;

        if let Some(expected_domain) = self.guarantee_domain.as_ref()
            && &claims.domain != expected_domain
        {
            let mut domain_hex = String::from("0x");
            for byte in claims.domain {
                write!(&mut domain_hex, "{byte:02x}").unwrap();
            }
            return Err(format!(
                "guarantee domain mismatch: got {domain_hex}, expected configured domain"
            ));
        }

        Ok(claims)
    }
}
