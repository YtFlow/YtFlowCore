use std::path::{Path, PathBuf};

pub use rusqlite::Connection;

mod embedded_migrations {
    use refinery::embed_migrations;
    embed_migrations!("src/data/migrations");
}

use super::*;

#[cfg(target_vendor = "uwp")]
fn setup_temp() {
    use windows::Storage::ApplicationData;

    use std::sync::Once;
    static SETUP_TEMP_ONCE: Once = Once::new();

    // Mark the library with LLVM dllimport storage class
    // See https://rust-lang.github.io/rfcs/1717-dllimport.html .
    #[link(name = "winsqlite3", kind = "dylib")]
    extern "C" {
        static mut sqlite3_temp_directory: *mut ::std::os::raw::c_char;
    }

    fn setup_temp_core() -> windows::core::Result<()> {
        use std::ffi::CString;
        let temp_path = ApplicationData::Current()?
            .TemporaryFolder()?
            .Path()?
            .to_string_lossy();
        unsafe {
            let c_path = CString::new(temp_path).unwrap();
            let sqlite_dir =
                rusqlite::ffi::sqlite3_mprintf(b"%s\0".as_ptr() as *const _, c_path.as_ptr());
            sqlite3_temp_directory = sqlite_dir;
        }
        Ok(())
    }

    SETUP_TEMP_ONCE.call_once(|| setup_temp_core().unwrap());
}

#[cfg(not(target_vendor = "uwp"))]
fn setup_temp() {}

#[derive(Clone)]
pub struct Database {
    path: PathBuf,
}

fn connect(path: impl AsRef<Path>) -> DataResult<Connection> {
    setup_temp();
    let db = Connection::open(&path)?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    Ok(db)
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> DataResult<Database> {
        let mut db = connect(&path)?;
        embedded_migrations::migrations::runner().run(&mut db)?;
        Ok(Database {
            path: path.as_ref().to_path_buf(),
        })
    }

    pub fn connect(&self) -> DataResult<Connection> {
        connect(self.path.as_path())
    }

    pub fn connect_temp() -> DataResult<Connection> {
        setup_temp();
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        embedded_migrations::migrations::runner().run(&mut db)?;
        Ok(db)
    }
}
