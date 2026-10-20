use std::num::NonZeroUsize;

use crate::pkcs11::ObjectHandle;

use super::super::{
    error::{Error, Function, Result, Rv},
    pkcs11_sys::*,
};

use super::Session;

#[derive(Debug)]
pub struct ObjectHandleIterator<'a> {
    session: &'a Session,
    object_count: usize,
    index: usize,
    objects: Vec<CK_OBJECT_HANDLE>,
}

impl<'a> ObjectHandleIterator<'a> {
    pub fn new(
        session: &'a Session,
        mut template: Vec<CK_ATTRIBUTE>,
        cache_size: NonZeroUsize,
    ) -> Result<Self> {
        unsafe {
            let rv = (session.client().functions.C_FindObjectsInit)
                .ok_or(Error::NullFunctionPointer)?(
                session.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            );

            Rv::from(rv).into_result(Function::FindObjectsInit)?
        }

        let objects: Vec<CK_OBJECT_HANDLE> = vec![0; cache_size.get()];
        Ok(ObjectHandleIterator {
            session,
            object_count: cache_size.get(),
            index: cache_size.get(),
            objects,
        })
    }
}

impl<'a> Iterator for ObjectHandleIterator<'a> {
    type Item = Result<ObjectHandle>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.object_count > 0 {
            if self.index < self.object_count {
                self.index += 1;
                return Some(Ok(ObjectHandle::new(self.objects[self.index - 1])));
            } else {
                self.index = 0;
                if self.object_count < self.objects.len() {
                    self.object_count = 0;
                    break;
                } else {
                    self.object_count = 0;
                }
            }
            unsafe {
                let rv = (self.session.client().functions.C_FindObjects).unwrap()(
                    self.session.handle(),
                    self.objects.as_mut_ptr(),
                    self.objects.len() as CK_ULONG,
                    &mut self.object_count as *mut _ as *mut CK_ULONG,
                );

                match Rv::from(rv) {
                    Rv::Error(err) => return Some(Err(Error::Pkcs11(err, Function::FindObjects))),
                    Rv::Ok => {}
                }
            }
        }
        None
    }
}

impl<'a> Drop for ObjectHandleIterator<'a> {
    fn drop(&mut self) {
        unsafe {
            let rv = (self.session.client().functions.C_FindObjectsFinal).unwrap()(
                self.session.handle(),
            );

            if let Rv::Error(err) = Rv::from(rv) {
                eprintln!("C_FindObjectsFinal failed: {err:?}");
            }
        }
    }
}
