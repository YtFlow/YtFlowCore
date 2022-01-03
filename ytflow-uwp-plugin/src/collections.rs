use std::rc::Rc;
use windows::core::HRESULT;
use windows::core::{implement, Result, RuntimeType};

use crate::bindings::Windows;
use crate::bindings::Windows::Foundation::Collections::*;
use crate::bindings::Windows::Networking::HostName;

const E_BOUNDS: HRESULT = HRESULT(0x8000000B);

#[implement(
    Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName>,
    Windows::Foundation::Collections::IIterable<Windows::Networking::HostName>,
)]
pub struct SimpleHostNameVectorView(pub Rc<[HostName]>);

impl SimpleHostNameVectorView {
    fn First(&self) -> Result<IIterator<HostName>> {
        Ok(SimpleHostNameIter {
            data: Rc::clone(&self.0),
            cursor: 0,
        }
        .into())
    }

    fn GetAt(&self, index: u32) -> Result<HostName> {
        self.0
            .get(index as usize)
            .map(Clone::clone)
            .ok_or_else(|| E_BOUNDS.into())
    }

    fn Size(&self) -> Result<u32> {
        Ok(self.0.len() as u32)
    }

    fn IndexOf(&self, value: &Option<HostName>, result: &mut u32) -> Result<bool> {
        let value = match value.as_ref() {
            Some(v) => v,
            None => return Ok(false),
        };
        if let Some((index, _)) = self.0.iter().enumerate().find(|(_, v)| v.eq(&value)) {
            *result = index as _;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn GetMany(&self, start_index: u32, items: &mut [HostName]) -> Result<u32> {
        match self.0.get(start_index as usize..) {
            Some(sub_slice) => {
                items.clone_from_slice(sub_slice);
                Ok(sub_slice.len() as _)
            }
            None => Err(E_BOUNDS.into()),
        }
    }
}

#[implement(Windows::Foundation::Collections::IIterator<T>)]
struct SimpleHostNameIter<T: RuntimeType> {
    data: Rc<[T]>,
    cursor: usize,
}

impl<T: RuntimeType> SimpleHostNameIter<T> {
    fn Current(&self) -> Result<T> {
        match self.data.get(self.cursor) {
            Some(v) => Ok(v.clone()),
            None => Err(E_BOUNDS.into()),
        }
    }

    fn HasCurrent(&self) -> Result<bool> {
        Ok(self.cursor < self.data.len())
    }

    fn MoveNext(&mut self) -> Result<bool> {
        if self.cursor < self.data.len() {
            self.cursor += 1;
        }
        Ok(self.cursor < self.data.len())
    }

    fn GetMany(&self, items: &mut [T]) -> Result<u32> {
        match self.data.get(self.cursor..) {
            Some(sub_slice) => {
                items.clone_from_slice(sub_slice);
                Ok(sub_slice.len() as _)
            }
            None => Err(E_BOUNDS.into()),
        }
    }
}
