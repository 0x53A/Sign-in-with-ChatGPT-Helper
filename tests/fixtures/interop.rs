//! Synthetic cross-language fixture; never contacts OpenAI.
use chatgpt_login_helper::protocol::{self, Request, SCOPES, Tokens};
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let raw = protocol::read_package(&std::fs::read(&args[1])?, "request.json")?;
    let request = Request::parse(&raw)?;
    let tokens = Tokens {
        client_id: "oaiapp_test".into(),
        host_id: request.host_id.clone(),
        subject: "test-subject".into(),
        access_token: "synthetic-access".into(),
        refresh_token: "synthetic-refresh".into(),
        token_type: "Bearer".into(),
        scope: SCOPES.join(" "),
        expires_at: protocol::now() + 3600,
    };
    let result = protocol::encrypt(&raw, &request, &tokens)?;
    std::fs::write(
        &args[2],
        protocol::package("response.json", &serde_json::to_string(&result)?)?,
    )?;
    Ok(())
}
