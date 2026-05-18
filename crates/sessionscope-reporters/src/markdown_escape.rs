pub(crate) fn inline_text(value: &str) -> String {
    value
        .lines()
        .map(|line| escape_markdown_html(line.trim()))
        .collect::<Vec<_>>()
        .join("<br>")
}

pub(crate) fn table_cell(value: &str) -> String {
    inline_text(value)
}

pub(crate) fn code_span(value: impl AsRef<str>) -> String {
    let text = inline_html_text(value.as_ref());
    let longest_backtick_run = text.split(|ch| ch != '`').map(str::len).max().unwrap_or(0);
    let delimiter = "`".repeat(longest_backtick_run + 1);
    if text.starts_with('`') || text.ends_with('`') {
        format!("{delimiter} {text} {delimiter}")
    } else {
        format!("{delimiter}{text}{delimiter}")
    }
}

fn inline_html_text(value: &str) -> String {
    value
        .lines()
        .map(|line| escape_html(line.trim()))
        .collect::<Vec<_>>()
        .join("<br>")
}

fn escape_markdown_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '!' | '|' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(character),
        }
    }
    escaped
}
