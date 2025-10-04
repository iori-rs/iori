use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
};

pub struct DuplicateOutputFileNamer {
    output_path: PathBuf,
    /// The count of files that have been generated.
    file_count: u32,
    file_extension: String,
}

impl DuplicateOutputFileNamer {
    pub fn new(output_path: PathBuf) -> Self {
        let file_extension = output_path
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            .to_string();

        Self {
            output_path,
            file_count: 0,
            file_extension,
        }
    }

    pub fn next_path(&mut self) -> PathBuf {
        self.file_count += 1;
        self.get_path(self.file_count)
    }

    fn get_path(&self, file_id: u32) -> PathBuf {
        self.output_path
            .with_extension(format!("{file_id}.{}", self.file_extension))
    }
}

impl Drop for DuplicateOutputFileNamer {
    fn drop(&mut self) {
        if self.file_count == 1
            && let Err(e) = std::fs::rename(self.get_path(1), &self.output_path)
        {
            tracing::error!("Failed to rename file: {e}");
        }
    }
}

pub trait IoriPathExt {
    /// Add suffix to file name without changing extension.
    ///
    /// Note this function does not handle multiple suffixes.
    /// For example, `test.tar.gz` with `_suffix` will be `test.tar_suffix.gz`.
    fn add_suffix<T: AsRef<OsStr>>(&mut self, suffix: T);

    /// Set extension of current filename.
    ///
    /// If the extension is in the list of extensions allowed to replace,
    /// the extension will be replaced.
    ///
    /// Otherwise, the new extension will be appended to the current extension.
    fn replace_extension(&mut self, new_extension: &str, replace_list: &[&str]) -> bool;

    fn with_replaced_extension(&self, new_extension: &str, replace_list: &[&str]) -> PathBuf;
}

impl IoriPathExt for PathBuf {
    fn add_suffix<T: AsRef<OsStr>>(&mut self, suffix: T) {
        let mut filename = OsString::new();

        // {file_stem}_{suffix}.{ext}
        if let Some(file_stem) = self.file_stem() {
            filename.push(file_stem);
        }
        filename.push("_");
        filename.push(suffix);

        if let Some(ext) = self.extension() {
            filename.push(".");
            filename.push(ext);
        }

        self.set_file_name(filename);
    }

    fn replace_extension(&mut self, new_extension: &str, replace_list: &[&str]) -> bool {
        let current_extension = self.extension().map(|e| e.to_os_string());
        match current_extension {
            // if extension exists, check if it is in the replace list
            Some(mut ext) => {
                let should_replace = ext
                    .to_str()
                    .map(|ext_str| replace_list.contains(&ext_str))
                    .unwrap_or(false);

                if should_replace {
                    self.set_extension(new_extension)
                } else {
                    ext.push(".");
                    ext.push(new_extension);
                    self.set_extension(ext)
                }
            }
            // if extension does not exist, just set the new extension
            None => self.set_extension(new_extension),
        }
    }

    fn with_replaced_extension(&self, new_extension: &str, replace_list: &[&str]) -> PathBuf {
        let mut path = self.clone();
        path.replace_extension(new_extension, replace_list);
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_file_names() {
        let mut namer = DuplicateOutputFileNamer::new(PathBuf::from("output.ts"));
        for i in 1..=100 {
            assert_eq!(namer.next_path(), PathBuf::from(format!("output.{i}.ts")));
        }
    }

    #[test]
    fn test_filename_suffix() {
        let mut path = PathBuf::from("test.mp4");
        path.add_suffix("suffix");
        assert_eq!(path.to_string_lossy(), "test_suffix.mp4");
    }

    #[test]
    fn test_filename_multiple_suffix() {
        let mut path = PathBuf::from("test.raw.mp4");
        path.add_suffix("suffix");
        assert_eq!(path.to_string_lossy(), "test.raw_suffix.mp4");
    }

    #[test]
    fn test_replace_extension_in_replace_list() {
        let mut path = PathBuf::from("test.mp4");
        path.replace_extension("ts", &["mp4"]);
        assert_eq!(path.to_string_lossy(), "test.ts");
    }

    #[test]
    fn test_replace_extension_for_none_extension() {
        let mut path = PathBuf::from("test");
        path.replace_extension("ts", &["mp4"]);
        assert_eq!(path.to_string_lossy(), "test.ts");
    }

    #[test]
    fn test_replace_extension_not_in_replace_list() {
        let mut path = PathBuf::from("test.aws");
        path.replace_extension("ts", &["mkv"]);
        assert_eq!(path.to_string_lossy(), "test.aws.ts");
    }
}
