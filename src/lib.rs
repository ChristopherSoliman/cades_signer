use der::Decode;
use x509_cert::Certificate;

use crate::{
    cades::CadesBuilder,
    canonical_parser::CanonicalParser,
    pkcs11::{
        Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle, Pkcs11,
        Session,
    },
    token_signer_error::TokenSignerResult,
};

pub use token_signer_error::TokenSignerError;

mod cades;
mod canonical_parser;
mod pkcs11;
mod token_signer_error;

pub struct CadesSigner {
    pin: String,
    #[allow(unused)]
    pkcs: Pkcs11,
    session: Session,
    certificate: Option<Certificate>,
    certificate_id: Option<Vec<u8>>,
    private_key: Option<ObjectHandle>,
}

impl CadesSigner {
    /// For Windows use:
    /// ```
    /// let cades_signer = CadesSigner::initialize("eps2003csp11.dll").unwrap();
    /// ```
    /// For Unix use:
    /// ```
    /// let cades_signer = CadesSigner::initialize("libcastle.1.0.0.dylib").unwrap();
    /// ```
    pub fn initialize(pin: impl ToString, path: impl ToString) -> TokenSignerResult<Self> {
        let pkcs = Self::init_pkcs(path)?;
        let session = Self::init_session(&pkcs)?;
        let mut signer = CadesSigner {
            pin: pin.to_string(),
            pkcs: pkcs,
            session,
            certificate: None,
            certificate_id: None,
            private_key: None,
        };
        signer.get_certificate()?;
        signer.get_private_key()?;
        Ok(signer)
    }

    pub fn sign(&self, document_json: &str, verify: bool) -> TokenSignerResult<String> {
        let mut json = CanonicalParser::new(document_json.chars().peekable());
        let parsed_json = json.parse()?;
        let Some(ref certificate) = self.certificate else {
            return Err(TokenSignerError::NoCertificateFound);
        };

        let Some(private_key) = self.private_key else {
            return Err(TokenSignerError::NoPrivateKeyFound);
        };

        Ok(CadesBuilder::build(
            &self.session,
            &certificate,
            parsed_json.as_bytes(),
            &private_key,
            verify,
        )?)
    }

    fn init_pkcs(path: impl ToString) -> TokenSignerResult<Pkcs11> {
        let pkcs = Pkcs11::new(&path.to_string())?;
        // if cfg!(windows) {
        //     pkcs = Pkcs11::new("eps2003csp11")?;
        // } else if cfg!(unix) {
        //     pkcs = Pkcs11::new("/usr/local/lib/libcastle.1.0.0.dylib")?;
        // } else {
        //     return Err(TokenSignerError::InvalidOperatingSystem);
        // }
        pkcs.initialize()?;
        Ok(pkcs)
    }

    fn init_session(pkcs: &Pkcs11) -> TokenSignerResult<Session> {
        let slots = pkcs.get_token_slots()?;

        if slots.len() == 0 {
            return Err(TokenSignerError::NoSlotsAvailable);
        }
        Ok(pkcs.open_session(slots[0])?)
    }

    fn get_certificate(&mut self) -> TokenSignerResult<()> {
        let template = [
            Attribute::Token(true),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Class(ObjectClass::CERTIFICATE),
        ];

        let objects = self.session.find_objects(&template)?;

        let template = [AttributeType::Value, AttributeType::Id];
        let attr_values = self
            .session
            .get_object_attributes_value(objects[0], &template)
            .unwrap();

        let values: Vec<Vec<u8>> = attr_values
            .into_iter()
            .filter_map(|attr| match attr {
                Attribute::Value(x) => Some(x),
                Attribute::Id(x) => Some(x),
                _ => None,
            })
            .collect();

        if values.len() != 2 {
            return Err(TokenSignerError::InvalidCertficate);
        }
        let x509 = Certificate::from_der(&values[0])?;
        self.certificate_id = Some(values[1].clone());
        self.certificate = Some(x509);
        Ok(())
    }

    fn get_private_key(&mut self) -> TokenSignerResult<()> {
        if self.certificate_id.is_none() {
            return Err(TokenSignerError::NoCertificateFound);
        }
        let template = [
            Attribute::Token(true),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        loop {
            self.session.login(&self.pin.trim())?;
            break;
        }

        let objects = self.session.find_objects(&template)?;

        let template = [AttributeType::Id];
        let objects = objects
            .iter()
            .filter_map(|key| {
                let attr_values = self
                    .session
                    .get_object_attributes_value(*key, &template)
                    .unwrap();

                if let Attribute::Id(id) = &attr_values[0] {
                    if id == self.certificate_id.as_ref().unwrap() {
                        return Some(key);
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        if objects.len() < 1 {
            return Err(TokenSignerError::NoPrivateKeyFound);
        }

        self.private_key = Some(*objects[0]);
        Ok(())
    }
}
