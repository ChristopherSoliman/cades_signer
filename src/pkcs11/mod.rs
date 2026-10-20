#![allow(dead_code)]
use std::rc::Rc;

pub use error::{Error, Function, Result, Rv};
pub use objects::*;
pub use session::Session;
pub use slot::Slot;

#[cfg(target_os = "windows")]
use pkcs11_sys_windows as pkcs11_sys;

pub mod error;
mod mechanism;
mod objects;
#[cfg(target_os = "macos")]
mod pkcs11_sys;
#[cfg(target_os = "linux")]
mod pkcs11_sys;
#[cfg(target_os = "windows")]
mod pkcs11_sys_windows;
mod session;
mod slot;
mod types;

#[derive(Clone, Debug)]
pub struct Pkcs11 {
    _library: Rc<libloading::Library>,
    pub functions: pkcs11_sys::CK_FUNCTION_LIST,
}
/// Implementaion of PKCS #11 library
///
impl Pkcs11 {
    /// Create a new `Pcks11` instance.
    /// # Example
    /// ```
    /// use pcks11::Pksc11
    /// let pksc11 = Pkcs11::new("path_to_lib_file");
    /// ```
    pub fn new(path: &str) -> Result<Self> {
        unsafe {
            let library = libloading::Library::new(path)?;
            let pkcs_library = pkcs11_sys::Pkcs11::new(&library).map_err(Error::LibraryLoading)?;
            let mut list: pkcs11_sys::CK_FUNCTION_LIST_PTR = std::ptr::null_mut();

            let rv = pkcs_library.C_GetFunctionList(&mut list);
            Rv::from(rv).into_result(Function::GetFunctionList)?;

            Ok(Pkcs11 {
                _library: Rc::new(library),
                functions: *list,
            })
        }
    }

    /// Initialize the PKCS Library.
    ///
    /// This is required before calling any other functions. `finalize()` is called on drop
    ///
    /// # Example
    /// ```
    /// if let Err(e) = pkcs11.initialize(){
    ///     panic!("{}", e);
    /// };
    /// let slots = pkcs11.get_token_slots();
    /// ```
    pub fn initialize(&self) -> Result<()> {
        unsafe {
            let rv = (self.functions.C_Initialize).ok_or(Error::NullFunctionPointer)?(
                std::ptr::null_mut(),
            );
            return Rv::from(rv).into_result(Function::Initialize);
        }
    }

    /// Retrieve a list of slots with tokens
    ///
    /// # Example
    /// ```
    /// if let Err(e) = pkcs11.initialize(){
    ///     panic!("{}", e);
    /// }
    /// let slots = match pkcs.get_token_slots() {
    ///     Ok(s) => s,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// if slots > 0 {
    /// // Do something with them
    /// }
    /// ```
    pub fn get_token_slots(&self) -> Result<Vec<Slot>> {
        let mut token_slots = 0;
        unsafe {
            let rv = (self.functions.C_GetSlotList).ok_or(Error::NullFunctionPointer)?(
                pkcs11_sys::CK_TRUE,
                std::ptr::null_mut(),
                &mut token_slots,
            );
            Rv::from(rv).into_result(Function::GetSlotList)?;
        };

        let mut slots = vec![0; token_slots as usize];
        unsafe {
            let rv = (self.functions.C_GetSlotList).ok_or(Error::NullFunctionPointer)?(
                pkcs11_sys::CK_TRUE,
                slots.as_mut_ptr(),
                &mut token_slots,
            );
            Rv::from(rv).into_result(Function::GetSlotList)?;
        };

        Ok(slots.into_iter().map(Slot::new).collect())
    }

    /// Opens and returns a session on the provided slot
    ///
    /// # Example
    /// ```
    /// let session = match pkcs.open_session(slot) {
    ///     Ok(s) => s,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    pub fn open_session(&self, slot: Slot) -> Result<Session> {
        let mut session_handle = 0;

        let flags = pkcs11_sys::CKF_SERIAL_SESSION | pkcs11_sys::CKF_RW_SESSION;
        unsafe {
            let rv = (self.functions.C_OpenSession).ok_or(Error::NullFunctionPointer)?(
                slot.id(),
                flags,
                std::ptr::null_mut(),
                None,
                &mut session_handle,
            );
            Rv::from(rv).into_result(Function::OpenSession)?
        }
        Ok(Session::new(session_handle, self.clone()))
    }
}
impl Drop for Pkcs11 {
    fn drop(&mut self) {
        unsafe {
            self.functions.C_Finalize.unwrap()(std::ptr::null_mut());
        }
    }
}
