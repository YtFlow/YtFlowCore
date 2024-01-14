use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use ytflow::resource::{FileResourceLoader, ResourceResult};

pub struct FsResourceLoader {
    root: PathBuf,
}

impl FsResourceLoader {
    pub fn new(root: PathBuf) -> io::Result<Self> {
        Ok(Self {
            root: root.canonicalize()?,
        })
    }
    pub fn root(&self) -> &Path {
        self.root.as_path()
    }
}

impl FileResourceLoader for FsResourceLoader {
    fn load_file(&self, local_name: &str) -> ResourceResult<File> {
        let file_path = Path::join(&self.root, PathBuf::from(local_name)).canonicalize()?;
        if !file_path.starts_with(self.root.as_path()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "File path is outside of resource root",
            )
            .into());
        }
        let file = File::options().read(true).open(file_path)?;
        Ok(file)
    }
}
