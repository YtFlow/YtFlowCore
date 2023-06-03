use std::fs;
use std::io;
use std::os::windows::io::FromRawHandle;

use windows::core::{Interface, HSTRING};
use ytflow::resource::{FileResourceLoader, ResourceError, ResourceResult};

use crate::bindings::Windows::Storage::StorageFolder;
use crate::bindings::Windows::Win32::System::WinRT::Storage::IStorageItemHandleAccess;

const HAO_READ: u32 = 0x120089;
const HSO_SHARE_READ: u32 = 0x1;
const HO_NONE: u32 = 0;

pub(crate) struct StorageResourceLoader {
    pub(crate) root: StorageFolder,
}

// 😕
unsafe impl Send for StorageResourceLoader {}
unsafe impl Sync for StorageResourceLoader {}

fn hresult_to_resource(r: windows::core::Error) -> ResourceError {
    ResourceError::IoError(io::Error::from_raw_os_error(r.code().0 as i32))
}

impl FileResourceLoader for StorageResourceLoader {
    fn load_file(&self, local_name: &str) -> ResourceResult<fs::File> {
        let storage_file = self
            .root
            .GetFileAsync(HSTRING::try_from(local_name).unwrap())
            .map_err(hresult_to_resource)?
            .get()
            .map_err(hresult_to_resource)?;
        let handle_access: IStorageItemHandleAccess = storage_file.cast().unwrap();
        unsafe {
            let handle = handle_access
                .Create(HAO_READ.into(), HSO_SHARE_READ.into(), HO_NONE.into(), None)
                .map_err(hresult_to_resource)?;
            let file = fs::File::from_raw_handle(handle.0 as _);
            Ok(file)
        }
    }
}
