use crate::pkcs11;

#[derive(Debug)]
pub enum CadesBuilderError {
    DerError(der::Error),
    SigningError(pkcs11::Error),
}

impl std::fmt::Display for CadesBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CadesBuilderError::DerError(error) => write!(f, "DER parsing error: {error}"),
            CadesBuilderError::SigningError(error) => write!(f, "Signing error: {error}"),
        }
    }
}

impl std::error::Error for CadesBuilderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CadesBuilderError::DerError(error) => Some(error),
            CadesBuilderError::SigningError(error) => Some(error),
        }
    }
}

impl From<der::Error> for CadesBuilderError {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

impl From<pkcs11::Error> for CadesBuilderError {
    fn from(value: pkcs11::Error) -> Self {
        Self::SigningError(value)
    }
}
