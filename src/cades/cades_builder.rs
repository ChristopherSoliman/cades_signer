use super::signing_certificate_v2::*;
use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos},
};
use der::{
    AnyRef, Decode, Tag,
    asn1::{Any, OctetString, SequenceOf, SetOfVec},
};
use sha256;
use std::time::SystemTime;
use x509_cert::{
    Certificate,
    attr::{Attribute, AttributeValue},
    der::Encode,
    spki::{AlgorithmIdentifierOwned, ObjectIdentifier},
};

use super::CadesBuilderError;
use base64::prelude::*;

use crate::pkcs11::{ObjectHandle, Session};

// OIDs
const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA256_WITH_RSA_ENCRYPTIAN_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const DIGEST_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.5");
const CONTENT_TYPE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const SIGNING_CERTIFICATE_V2_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const SIGNED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

// Algorithm Identifiers
const SHA256_DIGEST_ALGORITHM: AlgorithmIdentifierOwned = AlgorithmIdentifierOwned {
    oid: SHA256_OID,
    parameters: None,
};
const SHA256_WITH_RSA_ENCRYPTION_DIGEST_ALGORITHM: AlgorithmIdentifierOwned =
    AlgorithmIdentifierOwned {
        oid: SHA256_WITH_RSA_ENCRYPTIAN_OID,
        parameters: None,
    };

pub struct CadesBuilder;

impl CadesBuilder {
    /// Returns a Base64 encoded string of the CMS structure as specified in RFC #5652. This is
    /// tailored for the Egyptian Tax Authority Electronic Invoicing.
    ///
    /// This is not a general solution and is intended to sign invoices for the ETA. The user is
    /// expected to have initiated a token session and obtained the certificate and private key.
    pub fn build(
        session: &Session,
        cert: &Certificate,
        data: &[u8],
        private_key: &ObjectHandle,
        verify: bool,
    ) -> Result<String, CadesBuilderError> {
        let data_hash = sha256::digest(data);
        let signed_attrs = Self::build_signed_attrs(&cert, &data_hash.as_bytes())?;
        let signed_attrs_der = signed_attrs.to_der()?;
        let signature = session.sign(&private_key, &signed_attrs_der)?;
        if verify {
            session.verify(&signed_attrs_der, &signature)?;
        }
        let cades = Self::build_cades(&cert, signed_attrs, &signature)?;
        let cades_b64 = BASE64_STANDARD.encode(cades);
        Ok(cades_b64)
    }

    /// Builds final CAdES structure
    fn build_cades(
        cert: &Certificate,
        signed_attrs: Vec<Attribute>,
        signature: &[u8],
    ) -> Result<Vec<u8>, CadesBuilderError> {
        let encap_data = EncapsulatedContentInfo {
            econtent_type: DIGEST_DATA_OID,
            econtent: None,
        };

        let signer_infos = Self::build_signer_infos(cert, signed_attrs, signature)?;

        let mut digest_algorithms: SetOfVec<AlgorithmIdentifierOwned> = SetOfVec::new();
        digest_algorithms.insert(SHA256_DIGEST_ALGORITHM)?;

        let certifcates = vec![CertificateChoices::Certificate(cert.clone())];

        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms,
            encap_content_info: encap_data,
            certificates: Some(certifcates.try_into()?),
            crls: None,
            signer_infos,
        };

        let signed_data_der = signed_data.to_der()?;
        let content = AnyRef::try_from(&signed_data_der as &[u8])?;

        let content_info = ContentInfo {
            content_type: SIGNED_DATA_OID,
            content: Any::from(content),
        };

        Ok(content_info.to_der()?)
    }

    /// Build SignerInfos
    fn build_signer_infos(
        cert: &Certificate,
        signed_attrs: Vec<Attribute>,
        signature: &[u8],
    ) -> Result<SignerInfos, CadesBuilderError> {
        // Create IssuerSerialNumber for Signer Identifier
        let issuer_serial = IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        };

        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(issuer_serial),
            digest_alg: SHA256_DIGEST_ALGORITHM,
            signature_algorithm: SHA256_WITH_RSA_ENCRYPTION_DIGEST_ALGORITHM,
            signed_attrs: Some(signed_attrs.try_into()?),
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        };

        let mut signer_infos: SetOfVec<SignerInfo> = SetOfVec::new();
        signer_infos.insert(signer_info)?;

        Ok(SignerInfos(signer_infos))
    }

    /// Build the content-type attribute with the value 'digestData'
    fn build_content_type_attribute() -> Result<Attribute, CadesBuilderError> {
        let content_type_value =
            AttributeValue::new(Tag::ObjectIdentifier, DIGEST_DATA_OID.as_bytes())?;
        let mut values = SetOfVec::new();
        values.insert(content_type_value)?;

        Ok(Attribute {
            oid: CONTENT_TYPE_OID,
            values,
        })
    }

    /// Build the message-digest attribute
    fn build_message_digest_attribute(digest_hash: &[u8]) -> Result<Attribute, CadesBuilderError> {
        let message_digest_value =
            AttributeValue::new(Tag::OctetString, OctetString::new(digest_hash)?.as_bytes())?;
        let mut values = SetOfVec::new();
        values.insert(message_digest_value)?;

        Ok(Attribute {
            oid: MESSAGE_DIGEST_OID,
            values,
        })
    }

    /// Builds the SigningCertificateV2 attribute
    fn build_signing_certificate_attribute(
        cert: &Certificate,
    ) -> Result<Attribute, CadesBuilderError> {
        let issuer_serial = IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        };

        // Get the sha256 hash of the certificate
        let cert_hash = sha256::digest(cert.to_der()?);

        let hash_algorithm = AlgorithmIdentifierOwned {
            oid: SHA256_OID,
            parameters: None,
        };

        // Create the ESSCertIDv2 object using the hash
        let ess_cert = ESSCertIDv2 {
            hash_algorithm,
            cert_hash: OctetString::new(cert_hash)?,
            issuer_serial,
        };

        // Create a new `SequenceOf<>` and add the ESSCertIDv2 to the sequence
        let mut certs: SequenceOf<ESSCertIDv2, 1> = SequenceOf::new();
        certs.add(ess_cert)?;

        let signing_certificate_v2 = SigningCertificateV2 { certs };

        // Create the signging certificate attribute value and add it to the `SetOfVec<>`
        let signing_certificate_value =
            AttributeValue::from_der(&signing_certificate_v2.to_der()?)?;
        let mut values = SetOfVec::new();
        values.insert(signing_certificate_value)?;

        Ok(Attribute {
            oid: SIGNING_CERTIFICATE_V2_OID,
            values,
        })
    }

    /// Builds the signing-time attribute based on the current time in UTC
    fn build_signing_time_attribute() -> Result<Attribute, CadesBuilderError> {
        let time_attr_value = AttributeValue::from_der(
            &der::asn1::UtcTime::from_system_time(SystemTime::now())?.to_der()?,
        )?;
        let mut values = SetOfVec::<AttributeValue>::new();
        values.insert(time_attr_value)?;

        Ok(Attribute {
            oid: SIGNING_TIME_OID,
            values,
        })
    }

    /// Builds the 4 required signed attributes
    ///     1. Content-Type with the value 'digestData'
    ///     2. Message-Digest using the provided digest
    ///     3. SigningCertificateV2 from the provided certficate
    ///     4. Signing-Time using the current time in UTC
    fn build_signed_attrs(
        cert: &Certificate,
        digest_hash: &[u8],
    ) -> Result<Vec<Attribute>, CadesBuilderError> {
        let content_type = Self::build_content_type_attribute()?;
        let message_digest = Self::build_message_digest_attribute(digest_hash)?;
        let ess_signing_cert = Self::build_signing_certificate_attribute(&cert)?;
        let time = Self::build_signing_time_attribute()?;
        Ok(vec![content_type, message_digest, ess_signing_cert, time])
    }
}
