use std::fmt::Display;

use crate::cades::CadesBuilderError;
use crate::canonical_parser::ParserError;
use crate::pkcs11::{Error as PkcsError, Function as PkcsFunction};
use der::Error as DerError;

#[derive(Debug)]
pub enum TokenSignerError {
    InvalidOperatingSystem,
    NoSlotsAvailable,
    InvalidCertficate,
    NoPrivateKeyFound,
    NoCertificateFound,
    IncorrectPin,
    CadesBuilderError(CadesBuilderError),
    InternalPkcsError(PkcsError),
    JsorParsingError(ParserError),
    CertificateParsingError,
}

impl Display for TokenSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSignerError::InvalidOperatingSystem => {
                write!(f, "Only Windows and Unix based systems supported")
            }
            TokenSignerError::NoCertificateFound => write!(f, "No valid certificate was found"),
            TokenSignerError::NoSlotsAvailable => write!(f, "No token slots available"),
            TokenSignerError::InvalidCertficate => write!(f, "Invalid certificate"),
            TokenSignerError::IncorrectPin => write!(f, "Incorrect pin"),
            TokenSignerError::InternalPkcsError(e) => write!(f, "Internal PKCS error: {e}"),
            TokenSignerError::JsorParsingError(error) => write!(f, "{error}",),
            TokenSignerError::CadesBuilderError(e) => write!(f, "Error building CAdES: {e}",),
            TokenSignerError::CertificateParsingError => {
                write!(f, "Error parsing certificate from token")
            }
            TokenSignerError::NoPrivateKeyFound => {
                write!(f, "No private key found for the given certificate")
            }
        }
    }
}

impl std::error::Error for TokenSignerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<crate::cades::CadesBuilderError> for TokenSignerError {
    fn from(value: crate::cades::CadesBuilderError) -> Self {
        Self::CadesBuilderError(value)
    }
}

impl From<PkcsError> for TokenSignerError {
    fn from(value: PkcsError) -> Self {
        if let PkcsError::Pkcs11(_, func) = value {
            if let PkcsFunction::Login = func {
                return TokenSignerError::IncorrectPin;
            }
        }
        TokenSignerError::InternalPkcsError(value)
    }
}

impl From<ParserError> for TokenSignerError {
    fn from(value: ParserError) -> Self {
        TokenSignerError::JsorParsingError(value)
    }
}

impl From<DerError> for TokenSignerError {
    fn from(_: DerError) -> Self {
        TokenSignerError::CertificateParsingError
    }
}

pub type TokenSignerResult<T> = core::result::Result<T, TokenSignerError>;
