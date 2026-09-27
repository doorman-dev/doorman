use serde_json::Value;
use tracing::info;

/// Log the legacy mock-email payload and report successful delivery.
pub async fn send_email(
    to_email: &str,
    subject: &str,
    body: &str,
    metadata: Option<&Value>,
) -> bool {
    info!(to = to_email, subject, "📧 [MOCK EMAIL]");
    info!(body, "mock email body");
    if let Some(metadata) = metadata {
        info!(metadata = %metadata, "mock email metadata");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_email_always_succeeds() {
        assert!(send_email("user@example.com", "Subject", "Body", None).await);
    }
}
