use super::pkcs11_sys::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Slot {
    slot_id: CK_SLOT_ID,
}

impl Slot {
    pub fn new(slot_id: CK_SLOT_ID) -> Self {
        Slot { slot_id }
    }

    pub fn id(&self) -> CK_SLOT_ID {
        self.slot_id.into()
    }
}
