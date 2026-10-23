//! The messages Forge sends, each as plain text and HTML. Links are absolute,
//! built from `server.public_base_url`.

/// A message's subject and its two bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// The message **Send test email** sends.
pub fn test_message(public_base_url: &str) -> Content {
    let base = public_base_url.trim_end_matches('/');
    let text = format!(
        "This is a test message from Forge at {base}.\n\n\
         Its email settings work: invitations and other mail will be sent the same way.\n"
    );
    let html = page(&format!(
        "<p>This is a test message from Forge at <a href=\"{href}\">{shown}</a>.</p>\
         <p>Its email settings work: invitations and other mail will be sent the same way.</p>",
        href = escape_html(base),
        shown = escape_html(base),
    ));
    Content {
        subject: "Forge test email".to_string(),
        text,
        html,
    }
}

/// An HTML document around `body`.
pub(crate) fn page(body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"></head>\
         <body style=\"font-family: sans-serif; line-height: 1.5\">{body}</body></html>"
    )
}

/// `text` safe to place in HTML text and in a double-quoted attribute.
pub(crate) fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_message_names_the_instance() {
        let m = test_message("https://forge.example.com/");
        assert_eq!(m.subject, "Forge test email");
        assert!(m.text.contains("https://forge.example.com."));
        assert!(m.html.contains("href=\"https://forge.example.com\""));
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            escape_html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        let m = test_message("https://x.example/<script>");
        assert!(!m.html.contains("<script>"));
    }
}
