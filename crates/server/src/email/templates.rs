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

/// The invitation (#322): the link with which `username` sets their password,
/// valid until `expires_at`. The link carries the token in its fragment,
/// which never reaches a server log or a `Referer`.
pub fn invitation(
    public_base_url: &str,
    username: &str,
    link: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Content {
    let base = public_base_url.trim_end_matches('/');
    let until = expires_at.format("%Y-%m-%d %H:%M UTC").to_string();
    let text = format!(
        "You have been given an account on Forge at {base}: {username}.\n\n\
         Choose your password here, before {until}:\n\n{link}\n\n\
         The link works once. If it has expired, ask your administrator for a new one.\n"
    );
    let html = page(&format!(
        "<p>You have been given an account on Forge at <a href=\"{base_href}\">{base_shown}</a>: \
         <strong>{user}</strong>.</p>\
         <p><a href=\"{link_href}\">Choose your password</a> before {until}.</p>\
         <p>Or open this link: {link_shown}</p>\
         <p>The link works once. If it has expired, ask your administrator for a new one.</p>",
        base_href = escape_html(base),
        base_shown = escape_html(base),
        user = escape_html(username),
        link_href = escape_html(link),
        link_shown = escape_html(link),
    ));
    Content {
        subject: "Your Forge account".to_string(),
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
    fn the_invitation_carries_the_link_and_the_expiry() {
        let expires = chrono::DateTime::parse_from_rfc3339("2026-10-26T09:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let m = invitation(
            "https://forge.example.com/",
            "alice@example.com",
            "https://forge.example.com/invite#tok&en",
            expires,
        );
        assert_eq!(m.subject, "Your Forge account");
        assert!(m.text.contains("alice@example.com"));
        assert!(m.text.contains("https://forge.example.com/invite#tok&en"));
        assert!(m.text.contains("2026-10-26 09:30 UTC"));
        assert!(m
            .html
            .contains("href=\"https://forge.example.com/invite#tok&amp;en\""));
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
