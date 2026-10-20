use cms::cert::IssuerAndSerialNumber;
use der::{
    asn1::{OctetString, SequenceOf},
    Sequence,
};
use x509_cert::spki::AlgorithmIdentifierOwned;

#[derive(Debug, Clone, Sequence)]
pub struct SigningCertificateV2<const N: usize> {
    pub certs: SequenceOf<ESSCertIDv2, N>,
}

#[derive(Debug, Clone, Sequence)]
pub struct ESSCertIDv2 {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub cert_hash: OctetString,
    pub issuer_serial: IssuerAndSerialNumber,
}
