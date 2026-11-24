use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FileDispositionInfo, SetFileInformationByHandle, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};

/// Strips only the DOS verbatim prefix, preserving non-DOS namespaces for rejection.
pub fn normalize_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(dos) = text.strip_prefix(r"\\?\") {
        if dos.as_bytes().get(1) == Some(&b':') {
            return PathBuf::from(dos);
        }
    }
    path.to_owned()
}

pub fn has_reparse_attribute(metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

pub fn is_reparse_point(path: &Path) -> io::Result<bool> {
    Ok(has_reparse_attribute(&fs::symlink_metadata(path)?))
}

pub fn is_junction_or_symlink(path: &Path) -> io::Result<bool> {
    is_reparse_point(path)
}

pub fn verify_plain_path(path: &Path) -> io::Result<()> {
    let ancestors: Vec<_> = path.ancestors().collect();
    for component in ancestors.into_iter().rev() {
        if is_reparse_point(component)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reparse point in path",
            ));
        }
    }
    Ok(())
}

fn lock_plain_directory(path: &Path) -> io::Result<File> {
    let handle = OpenOptions::new()
        .access_mode(1) // FILE_LIST_DIRECTORY
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let meta = handle.metadata()?;
    if !meta.is_dir() || has_reparse_attribute(&meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ancestor is not a plain directory",
        ));
    }
    Ok(handle)
}

/// Holds ancestor handles without delete sharing, then validates and deletes on the same file handle.
pub fn delete_file_checked(
    path: &Path,
    eligible: impl FnOnce(&Metadata) -> bool,
) -> io::Result<u64> {
    let ancestors: Vec<_> = path.ancestors().skip(1).collect();
    let _guards = ancestors
        .into_iter()
        .rev()
        .map(lock_plain_directory)
        .collect::<io::Result<Vec<_>>>()?;
    let file = OpenOptions::new()
        .access_mode(0x10000 | 0x80) // DELETE and FILE_READ_ATTRIBUTES
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || has_reparse_attribute(&metadata)
        || metadata.permissions().readonly()
        || !eligible(&metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file is protected or changed since inspection",
        ));
    }
    let info = FILE_DISPOSITION_INFO {
        DeleteFile: true.into(),
    };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
        .map_err(|error| {
            let code = error.code().0;
            if code as u32 >> 16 == 0x8007 {
                io::Error::from_raw_os_error(code & 0xffff)
            } else {
                io::Error::other(error)
            }
        })?;
    }
    Ok(metadata.len())
}

pub fn delete_file_safely(path: &Path) -> io::Result<()> {
    delete_file_checked(path, |_| true).map(|_| ())
}

pub fn delete_dir_safely_with_stats(path: &Path) -> io::Result<(u64, usize)> {
    verify_plain_path(path)?;
    let mut bytes = 0;
    let mut files = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if has_reparse_attribute(&metadata) {
            continue;
        }
        if metadata.is_dir() {
            let (child_bytes, child_files) = delete_dir_safely_with_stats(&entry.path())?;
            bytes += child_bytes;
            files += child_files;
        } else {
            bytes += delete_file_checked(&entry.path(), |_| true)?;
            files += 1;
        }
    }
    fs::remove_dir(path)?;
    Ok((bytes, files))
}

pub fn delete_dir_safely(path: &Path) -> io::Result<()> {
    delete_dir_safely_with_stats(path).map(|_| ())
}
