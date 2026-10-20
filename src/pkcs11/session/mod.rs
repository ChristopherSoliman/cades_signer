use std::num::NonZeroUsize;

use super::{
    AttributeInfo, AttributeType, Pkcs11, Result,
    error::{Error, Function, Rv},
    objects::Attribute,
    pkcs11_sys::*,
};
use crate::pkcs11::{KeyType, ObjectClass, objects::ObjectHandle};
use object_handling::ObjectHandleIterator;

mod object_handling;

const MAX_CACHE_SIZE: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(10) };

#[derive(Debug)]
pub struct Session {
    handle: CK_SESSION_HANDLE,
    client: Pkcs11,
}

impl Session {
    pub fn new(handle: CK_SESSION_HANDLE, client: Pkcs11) -> Self {
        Session { handle, client }
    }

    pub fn client(&self) -> &Pkcs11 {
        &self.client
    }

    pub fn handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    pub fn login(&self, pin: &str) -> Result<()> {
        unsafe {
            let rv = (self.client.functions.C_Login).ok_or(Error::NullFunctionPointer)?(
                self.handle,
                1,
                pin.as_ptr() as *mut u8,
                pin.len().try_into()?,
            );
            Rv::from(rv).into_result(Function::Login)
        }
    }

    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        let template: Vec<CK_ATTRIBUTE> = template.iter().map(Into::into).collect();
        let object_iterator = ObjectHandleIterator::new(&self, template, MAX_CACHE_SIZE)?;
        object_iterator.collect()
    }

    pub fn get_attribute_info(
        &self,
        object_handle: ObjectHandle,
        attr_list: &[AttributeType],
    ) -> Result<Vec<AttributeInfo>> {
        let mut allocation: Vec<AttributeInfo> = Vec::new();
        for attrib in attr_list {
            let mut template: Vec<CK_ATTRIBUTE> = vec![CK_ATTRIBUTE {
                type_: (*attrib).into(),
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            }];

            match unsafe {
                Rv::from((self.client.functions.C_GetAttributeValue)
                    .ok_or(Error::NullFunctionPointer)?(
                    self.handle(),
                    object_handle.handle(),
                    template.as_mut_ptr(),
                    template.len().try_into()?,
                ))
            } {
                Rv::Ok => {
                    allocation.push(AttributeInfo::Available(template[0].ulValueLen.try_into()?));
                }
                rv => rv.into_result(Function::GetAttributeValue)?,
            };
        }

        Ok(allocation)
    }

    pub fn get_object_attributes_value(
        &self,
        object_handle: ObjectHandle,
        attr_list: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        let attr_info = self.get_attribute_info(object_handle, attr_list)?;
        let attr_memory: Vec<(AttributeType, Vec<u8>)> = attr_info
            .iter()
            .zip(attr_list.iter())
            .filter_map(|(attr_info, attr_type)| {
                if let AttributeInfo::Available(size) = attr_info {
                    Some((*attr_type, vec![0; *size]))
                } else {
                    None
                }
            })
            .collect();

        let mut template: Vec<CK_ATTRIBUTE> = attr_memory
            .iter()
            .map(|(attr_type, memory)| {
                Ok(CK_ATTRIBUTE {
                    type_: (*attr_type).into(),
                    pValue: memory.as_ptr() as *mut std::ffi::c_void,
                    ulValueLen: memory.len().try_into()?,
                })
            })
            .collect::<Result<Vec<CK_ATTRIBUTE>>>()?;

        unsafe {
            let rv = (self.client.functions.C_GetAttributeValue)
                .ok_or(Error::NullFunctionPointer)?(
                self.handle(),
                object_handle.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            );
            Rv::from(rv).into_result(Function::GetAttributeValue)?;
            template.into_iter().map(|attr| attr.try_into()).collect()
        }
    }

    pub fn sign(&self, key: &ObjectHandle, data: &[u8]) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut signature_len = 0;
        unsafe {
            let rv = (self.client().functions.C_SignInit).ok_or(Error::NullFunctionPointer)?(
                self.handle(),
                &mut mechanism as *mut _ as CK_MECHANISM_PTR,
                key.handle(),
            );

            Rv::from(rv).into_result(Function::SignInit)?;

            let rv = (self.client().functions.C_Sign).ok_or(Error::NullFunctionPointer)?(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len() as CK_ULONG,
                std::ptr::null_mut(),
                &mut signature_len,
            );

            Rv::from(rv).into_result(Function::Sign)?;
        }

        let mut signature = vec![0; signature_len as usize];

        unsafe {
            let rv = (self.client().functions.C_Sign).ok_or(Error::NullFunctionPointer)?(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &mut signature_len,
            );

            Rv::from(rv).into_result(Function::Sign)?;
        }

        Ok(signature)
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        unsafe {
            let Some(public_key) = self.get_public_key()? else {
                return Rv::Error(crate::pkcs11::error::RvError::PublicKeyInvalid)
                    .into_result(Function::VerifyInit);
            };
            let rv = (self.client().functions.C_VerifyInit).ok_or(Error::NullFunctionPointer)?(
                self.handle(),
                &mut mechanism as *mut CK_MECHANISM,
                public_key.handle(),
            );
            Rv::from(rv).into_result(Function::VerifyInit)?;

            let rv = (self.client().functions.C_Verify).ok_or(Error::NullFunctionPointer)?(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len() as CK_ULONG,
                signature.as_ptr() as *mut u8,
                signature.len() as CK_ULONG,
            );
            Rv::from(rv).into_result(Function::Verify)?;
        }
        Ok(())
    }

    fn get_public_key(&self) -> Result<Option<ObjectHandle>> {
        let template = [
            Attribute::Token(true),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ];

        let objects = self.find_objects(&template)?;
        let template = [AttributeType::Verify];

        let objects = objects
            .iter()
            .filter_map(|key| {
                let attr_values = self.get_object_attributes_value(*key, &template).unwrap();

                if let Attribute::Verify(id) = &attr_values[0] {
                    if *id {
                        return Some(key);
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        if objects.len() < 1 {
            return Ok(None);
        }

        Ok(Some(*objects[0]))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            self.client().functions.C_Logout.unwrap()(self.handle);
        }
    }
}
