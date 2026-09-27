use std::sync::LazyLock;

static HTML_TAG: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"<[^>]+>").expect("HTML tag expression is valid"));
static UNSAFE_USERNAME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"[^a-zA-Z0-9_\-.@]").expect("username expression is valid")
});
static UNSAFE_API_NAME: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"[^a-zA-Z0-9_-]").expect("API-name expression is valid"));

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub fn sanitize_html(text: &str, allow_tags: bool) -> String {
    if allow_tags {
        html_escape(text)
    } else {
        html_escape(&HTML_TAG.replace_all(text, ""))
    }
}

pub fn sanitize_input(text: &str, max_length: Option<usize>) -> String {
    let sanitized = sanitize_html(text, false).replace('\0', "");
    let normalized = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
    match max_length.filter(|maximum| normalized.chars().count() > *maximum) {
        Some(maximum) => normalized.chars().take(maximum).collect(),
        None => normalized,
    }
}

pub fn sanitize_url(url: &str) -> String {
    let url = crate::python_scalar::strip(url);
    let lower = url.to_lowercase();
    if ["javascript:", "data:", "vbscript:", "file:", "about:"]
        .iter()
        .any(|scheme| lower.starts_with(scheme))
    {
        String::new()
    } else {
        url.to_owned()
    }
}

pub fn strip_control_characters(text: &str) -> String {
    text.chars()
        .filter(|character| *character as u32 >= 32 || matches!(character, '\n' | '\r' | '\t'))
        .collect()
}

pub fn sanitize_username(username: &str) -> String {
    let sanitized = sanitize_html(username, false);
    UNSAFE_USERNAME.replace_all(&sanitized, "").into_owned()
}

pub fn sanitize_api_name(name: &str) -> String {
    let sanitized = sanitize_html(name, false);
    UNSAFE_API_NAME.replace_all(&sanitized, "").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizers_match_python_examples_and_character_limits() {
        assert_eq!(sanitize_html("<b>A&B</b>", false), "A&amp;B");
        assert_eq!(
            sanitize_html("<b>A&B</b>", true),
            "&lt;b&gt;A&amp;B&lt;/b&gt;"
        );
        assert_eq!(
            sanitize_input("  <b>hello</b>\0  world  ", Some(8)),
            "hello wo"
        );
        assert_eq!(sanitize_url(" JAVASCRIPT:alert(1) "), "");
        assert_eq!(strip_control_characters("a\u{1}b\nc"), "ab\nc");
        assert_eq!(sanitize_username("<b>a</b>!._-@"), "a._-@");
        assert_eq!(sanitize_api_name("api name/v1"), "apinamev1");
    }
}
