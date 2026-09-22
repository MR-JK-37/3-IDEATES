use std::path::Path;

use crate::engines::DetectionResult;

const NON_EXEC_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "svg", "ico", "avif", "heic", "mp3",
    "mp4", "mkv", "avi", "mov", "flac", "ogg", "wav", "aac", "m4a", "md", "txt", "rst", "csv",
    "json", "yaml", "toml", "xml", "html", "css", "ttf", "otf", "woff", "woff2",
];

const SCREENSHOT_PATTERNS: &[&str] = &[
    "screenshot",
    "screen_shot",
    "capture",
    "img_",
    "snip",
    "photo",
];

const CACHE_PATH_HINTS: &[&str] = &[
    "/.cache/",
    "/mesa_shader_cache/",
    "/thumbnails/",
    "/cache/",
    "/browser-cache/",
];

pub fn is_non_executable_extension(ext: &str) -> bool {
    NON_EXEC_EXTENSIONS.contains(&ext)
}

pub fn is_known_user_content_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("/pictures/")
        || p.contains("/screenshots/")
        || p.contains("/downloads/")
        || p.contains("/documents/")
        || p.contains("/desktop/")
        || p.contains("/videos/")
        || p.contains("/music/")
}

pub fn is_cache_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    CACHE_PATH_HINTS.iter().any(|h| p.contains(h))
}

pub fn is_screenshot_name(path: &str) -> bool {
    let file = Path::new(path)
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    SCREENSHOT_PATTERNS.iter().any(|p| file.contains(p))
}

pub fn file_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(target_family = "unix")]
pub fn has_exec_permission(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

#[cfg(not(target_family = "unix"))]
pub fn has_exec_permission(_path: &str) -> bool {
    false
}

pub fn should_suppress_detection(path: &str, detection: &DetectionResult) -> bool {
    let ext = file_extension(path);
    let non_exec_ext = is_non_executable_extension(&ext);
    let cache_path = is_cache_path(path);
    let screenshot = is_screenshot_name(path);
    let user_content = is_known_user_content_path(path);
    let exec_perm = has_exec_permission(path);
    let ml_or_heuristic = detection.engine == "AI-RiskModel" || detection.engine == "Heuristic";
    let weak = detection.confidence < 0.97;

    if !ml_or_heuristic {
        return false;
    }

    if screenshot || (non_exec_ext && weak) {
        return true;
    }

    // Binary blobs in cache directories are often high entropy but benign.
    if cache_path && !exec_perm {
        return true;
    }

    // User media/docs should require very strong corroboration before alerting.
    if user_content && non_exec_ext && weak {
        return true;
    }

    false
}

