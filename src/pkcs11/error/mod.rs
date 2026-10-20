mod function;
mod rv;
mod rv_error;

pub use function::Function;
pub use rv::*;
pub use rv_error::*;

#[derive(Debug)]
pub enum Error {
    LibraryLoading(libloading::Error),
    Pkcs11(RvError, Function),
    TryFromInt(std::num::TryFromIntError),
    TryFromSlice(std::array::TryFromSliceError),
    NullFunctionPointer,
    NotSupported,
    InvalidValue,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::LibraryLoading(e) => write!(f, "libloading error: {e}"),
            Error::Pkcs11(rv, func) => write!(f, "{func}: PKCS11 Error: {rv}"),
            Error::InvalidValue => write!(f, "The value is not one of the expected options"),
            Error::NotSupported => write!(f, "The value is not supported"),
            Error::TryFromInt(e) => write!(f, "Conversion from integer failed {e}"),
            Error::NullFunctionPointer => write!(f, "Pointer to function is null"),
            Error::TryFromSlice(e) => write!(f, "Conversion from slice failed {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::LibraryLoading(e) => Some(e),
            Error::TryFromInt(e) => Some(e),
            Error::TryFromSlice(e) => Some(e),
            Error::Pkcs11(_, _)
            | Error::InvalidValue
            | Error::NotSupported
            | Error::NullFunctionPointer => None,
        }
    }
}

impl From<libloading::Error> for Error {
    fn from(value: libloading::Error) -> Self {
        Error::LibraryLoading(value)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(value: std::num::TryFromIntError) -> Self {
        Error::TryFromInt(value)
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(value: std::array::TryFromSliceError) -> Self {
        Error::TryFromSlice(value)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
