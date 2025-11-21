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

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_4mica::bls::{BLSCert as RawCert, pub_key_from_scalar};
    use rust_sdk_4mica::{PaymentGuaranteeClaims, U256};

    fn build_claims(domain: [u8; 32]) -> PaymentGuaranteeClaims {
        PaymentGuaranteeClaims {
            domain,
            user_address: "0x0000000000000000000000000000000000000001".into(),
            recipient_address: "0x0000000000000000000000000000000000000002".into(),
            tab_id: U256::from(1u8),
            req_id: U256::from(1u8),
            amount: U256::from(10u8),
            total_amount: U256::from(10u8),
            asset_address: "0x0000000000000000000000000000000000000003".into(),
            timestamp: 123,
            version: 1,
        }
    }

    fn build_cert(domain: [u8; 32]) -> (BLSCert, [u8; 48]) {
        let claims = build_claims(domain);
        let secret = [1u8; 32];
        let cert = RawCert::new(&secret, claims).expect("build cert");
        let pubkey_vec = pub_key_from_scalar(&secret).expect("pubkey");
        let pubkey: [u8; 48] = pubkey_vec.try_into().expect("48-byte key");
        (
            BLSCert {
                claims: cert.claims,
                signature: cert.signature,
            },
            pubkey,
        )
    }

    #[test]
    fn accepts_matching_domain() {
        let (cert, pubkey) = build_cert([0u8; 32]);
        let verifier = CertificateVerifier::new(pubkey, Some([0u8; 32]));
        let claims = verifier.verify_certificate(&cert).expect("valid cert");
        assert!(
            claims
                .recipient_address
                .to_ascii_lowercase()
                .ends_with("00000002"),
            "unexpected recipient address {}",
            claims.recipient_address
        );
    }

    #[test]
    fn rejects_domain_mismatch() {
        let (cert, pubkey) = build_cert([0u8; 32]);
        let verifier = CertificateVerifier::new(pubkey, Some([1u8; 32]));
        let err = verifier
            .verify_certificate(&cert)
            .expect_err("expected mismatch");
        assert!(
            err.contains("guarantee domain mismatch"),
            "unexpected error: {err}"
        );
    }
}
