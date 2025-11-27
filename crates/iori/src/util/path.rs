use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use crate::{IoriError, IoriResult};
use futures::FutureExt;
pub use sanitize_filename_reader_friendly::sanitize;

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

    fn sanitize(self) -> PathBuf;

    fn deduplicate(self) -> IoriResult<PathBuf>;

    fn non_empty_file_exists(&self) -> bool;
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

    /// Sanitize the path to make it filesystem-compatible and reader-friendly.
    ///
    /// This method sanitizes all path components (directories and filename) using
    /// the `sanitize-filename-reader-friendly` crate, which:
    /// - Replaces non-filesystem compatible characters with underscores and spaces
    /// - Replaces unprintable punctuation with underscores
    /// - Replaces other unprintable characters with spaces
    /// - Replaces newlines with hyphens
    /// - Trims underscores and spaces at the beginning, end, or when repeated
    ///
    /// This ensures maximum compatibility across different operating systems while
    /// keeping filenames readable.
    fn sanitize(self) -> PathBuf {
        use std::path::Component;

        let mut result = PathBuf::new();
        let components: Vec<_> = self.components().collect();

        for component in components.iter() {
            match component {
                Component::Normal(name) => {
                    if let Some(name_str) = name.to_str() {
                        let sanitized = sanitize_filename_reader_friendly::sanitize(name_str);
                        result.push(sanitized);
                    } else {
                        // If conversion fails, keep original
                        result.push(name);
                    }
                }
                component => {
                    result.push(component);
                }
            }
        }

        result
    }

    fn deduplicate(mut self) -> IoriResult<PathBuf> {
        let mut current_layer = 0;
        while self.exists() {
            current_layer += 1;

            // {filename}_{timestamp}_{layer}_{layer}
            if current_layer == 1 {
                let timestamp = chrono::Utc::now().timestamp();
                self.add_suffix(format!("{timestamp}"));
            } else if current_layer == 2 || current_layer == 3 {
                self.add_suffix(format!("{current_layer}"));
            } else {
                return Err(IoriError::IOError(std::io::Error::other(
                    "Failed to deduplicate file",
                )));
            }
        }
        Ok(self)
    }

    /// The path is file and it exists
    fn non_empty_file_exists(&self) -> bool {
        self.metadata()
            .map(|m| m.is_file() && m.len() > 0)
            .unwrap_or(false)
    }
}

pub struct SystemDotFiles {
    pub root: PathBuf,
}

impl SystemDotFiles {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn scan<F>(&self, recursive: bool, action: F) -> IoriResult<()>
    where
        F: Fn(PathBuf) -> std::pin::Pin<Box<dyn Future<Output = IoriResult<()>> + Send>>
            + Copy
            + Send,
    {
        SystemDotFiles::do_scan(&self.root, recursive, action).await
    }

    #[async_recursion::async_recursion]
    async fn do_scan<P, F>(path: P, recursive: bool, action: F) -> IoriResult<()>
    where
        P: AsRef<Path> + Send,
        F: Fn(PathBuf) -> std::pin::Pin<Box<dyn Future<Output = IoriResult<()>> + Send>>
            + Copy
            + Send,
    {
        let mut entries = tokio::fs::read_dir(path).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() && recursive {
                SystemDotFiles::do_scan(entry.path(), recursive, action).await?;
            }
            if entry.file_type().await?.is_file() {
                match entry.file_name().to_string_lossy().as_bytes() {
                    b".DS_Store" => {
                        action(entry.path()).await?;
                    }
                    b".directory" => {
                        action(entry.path()).await?;
                    }
                    file_name if file_name.starts_with(b"._") => {
                        // https://en.wikipedia.org/wiki/AppleSingle_and_AppleDouble_formats
                        action(entry.path()).await?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub async fn clean(&self, recursive: bool) -> IoriResult<()> {
        self.scan(recursive, |path| {
            async {
                tokio::fs::remove_file(path).await?;
                Ok(())
            }
            .boxed()
        })
        .await
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
    fn test_replace_extension_in_replace_list_multiple_suffix() {
        // 【ご来賓:水野朔さん】和久井優と土屋李央の「放課後が終わらない！」#63【土屋さんBD】.1..mp4
        let path = PathBuf::from(
            "【ご来賓:水野朔さん】和久井優と土屋李央の「放課後が終わらない！」#63【土屋さんBD】.1.",
        );
        let result = path.with_replaced_extension("mp4", &["mp4", "mkv", "ts"]);
        assert_eq!(
            result,
            PathBuf::from(
                "【ご来賓:水野朔さん】和久井優と土屋李央の「放課後が終わらない！」#63【土屋さんBD】.1..mp4"
            )
        );
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

    #[test]
    fn test_sanitize_normal_filename() {
        let path = PathBuf::from("test.mp4");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "test.mp4");
    }

    #[test]
    fn test_sanitize_filename_with_special_chars() {
        // Windows disallows: < > : " / \ | ? *
        let path = PathBuf::from("test:file?.mp4");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "test_file_.mp4");
    }

    #[test]
    fn test_sanitize_filename_ending_with_space() {
        // The library replaces dots with spaces in certain contexts
        let path = PathBuf::from("test .mp4");
        let sanitized = path.sanitize();
        // Note: behavior depends on the sanitize-filename-reader-friendly library
        assert_eq!(sanitized.to_string_lossy(), "test mp4");
    }

    #[test]
    fn test_sanitize_filename_ending_with_dot() {
        // The library preserves dots
        let path = PathBuf::from("test..mp4");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "test..mp4");
    }

    #[test]
    fn test_sanitize_japanese_filename() {
        // Japanese characters should be preserved
        let path = PathBuf::from(
            "【ご来賓:水野朔さん】和久井優と土屋李央の「放課後が終わらない！」#63【土屋さんBD】.mp4",
        );
        let sanitized = path.sanitize();
        // The colon should be replaced with underscore
        assert!(sanitized.to_string_lossy().contains("_"));
        assert!(!sanitized.to_string_lossy().contains(":"));
    }

    #[test]
    fn test_sanitize_with_path() {
        // Should sanitize all path components
        let path = PathBuf::from("some/path/test:file.mp4");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "some/path/test_file.mp4");
    }

    #[test]
    fn test_sanitize_path_with_special_chars_in_dirs() {
        // Should sanitize directory names too
        let path = PathBuf::from("folder:name/sub?dir/file.txt");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "folder_name/sub_dir/file.txt");
    }

    #[test]
    fn test_sanitize_path_with_reserved_dir_names() {
        // Note: sanitize-filename-reader-friendly doesn't add prefix to reserved names
        let path = PathBuf::from("CON/PRN/file.txt");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "CON/PRN/file.txt");
    }

    #[test]
    fn test_sanitize_path_with_trailing_dots_in_dirs() {
        // The library removes trailing dots from path components
        let path = PathBuf::from("folder./subdir../file.txt");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "folder/subdir/file.txt");
    }

    #[test]
    fn test_sanitize_all_special_chars() {
        // Note: '/' is a path separator and will cause PathBuf to split the path,
        // The library replaces special chars with underscores and spaces for readability
        let path = PathBuf::from(r#"file<>:"\|?*.txt"#);
        let sanitized = path.sanitize();
        // The exact output depends on sanitize-filename-reader-friendly's behavior
        assert_eq!(sanitized.to_string_lossy(), "file _ _ txt");
    }

    #[test]
    fn test_sanitize_preserves_path_structure() {
        // Forward slash is a path separator, structure should be preserved
        let path = PathBuf::from("file/name.txt");
        let sanitized = path.sanitize();
        // Path structure should be preserved
        assert_eq!(sanitized.to_string_lossy(), "file/name.txt");
    }

    #[test]
    fn test_sanitize_absolute_path() {
        // Test absolute path
        let path = PathBuf::from("/home/user:name/file?.txt");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "/home/user_name/file_.txt");
    }

    #[test]
    fn test_sanitize_multiple_trailing_chars() {
        // The library preserves dots and converts some to spaces
        let path = PathBuf::from("test... .mp4");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "test... mp4");
    }

    #[test]
    fn test_sanitize_reserved_name_without_extension() {
        // Note: sanitize-filename-reader-friendly doesn't modify reserved names
        let path = PathBuf::from("NUL");
        let sanitized = path.sanitize();
        assert_eq!(sanitized.to_string_lossy(), "NUL");
    }

    #[test]
    fn test_sanitize_com_lpt_names() {
        // Note: sanitize-filename-reader-friendly doesn't modify reserved names
        let path1 = PathBuf::from("COM1.txt");
        let sanitized1 = path1.sanitize();
        assert_eq!(sanitized1.to_string_lossy(), "COM1.txt");

        let path2 = PathBuf::from("LPT9.log");
        let sanitized2 = path2.sanitize();
        assert_eq!(sanitized2.to_string_lossy(), "LPT9.log");
    }
}
