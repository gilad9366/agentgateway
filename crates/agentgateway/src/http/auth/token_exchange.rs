use ::http::header::{ACCEPT, CONTENT_TYPE};
use secrecy::SecretString;
use serde::Deserialize;
use tracing::{debug, trace};
use url::form_urlencoded;

use crate::client::Client;
use crate::http::Body;
use crate::json;
use crate::serdes::schema;
use crate::{apply, http};

/// RFC 8693 OAuth 2.0 Token Exchange backend auth.
///
/// On every upstream call the gateway exchanges the validated inbound JWT for
/// an upstream-scoped access token by calling a configured token endpoint and
/// attaches the returned token as `Authorization: Bearer <token>`. The token
/// endpoint is responsible for validating the subject token and deciding which
/// token (if any) to issue.
///
/// # Behavior
///
/// - 2xx with `access_token` → token is set on the upstream request.
/// - 4xx → no token is attached; the upstream returns 401 and the caller can
///   drive a "link this integration" flow.
/// - Network failure / 5xx / malformed body → `BackendAuthenticationFailed`.
///
/// # Security
///
/// The inbound JWT is forwarded verbatim as `subject_token`. Configure the
/// token endpoint over TLS or a trusted in-cluster network.
#[apply(schema!)]
pub struct TokenExchangeAuth {
	/// RFC 8693 token endpoint URL.
	pub token_endpoint: String,
	/// `audience` parameter sent on the token-exchange request, identifying
	/// the upstream this backend is going to call.
	pub audience: String,
}

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const SUBJECT_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

#[derive(Debug, Deserialize)]
struct TokenResponse {
	access_token: String,
	#[serde(default)]
	token_type: Option<String>,
}

/// Exchange the subject token for an upstream-scoped access token.
///
/// `Ok(Some(_))` — exchange succeeded.
/// `Ok(None)`    — token endpoint rejected with a 4xx; the caller leaves the
///                 upstream request unauthenticated.
/// `Err(_)`      — transport failure / 5xx / malformed response.
pub(crate) async fn fetch_token(
	client: &Client,
	auth: &TokenExchangeAuth,
	subject_token: &str,
) -> anyhow::Result<Option<SecretString>> {
	let body = form_urlencoded::Serializer::new(String::new())
		.append_pair("grant_type", GRANT_TYPE)
		.append_pair("subject_token", subject_token)
		.append_pair("subject_token_type", SUBJECT_TOKEN_TYPE_JWT)
		.append_pair("audience", &auth.audience)
		.finish();

	let req = ::http::Request::builder()
		.method(::http::Method::POST)
		.uri(&auth.token_endpoint)
		.header(CONTENT_TYPE, "application/x-www-form-urlencoded")
		.header(ACCEPT, "application/json")
		.body(Body::from(body.into_bytes()))?;

	let resp = client
		.simple_call(req)
		.await
		.map_err(|e| anyhow::anyhow!("token exchange request failed: {e}"))?;

	let status = resp.status();
	if status.is_client_error() {
		debug!(
			"token exchange rejected for audience={}: status={}",
			auth.audience, status
		);
		return Ok(None);
	}
	if !status.is_success() {
		anyhow::bail!("token exchange returned status: {status}");
	}

	let limit = http::response_buffer_limit(&resp);
	let parsed: TokenResponse = json::from_body_with_limit(resp.into_body(), limit)
		.await
		.map_err(|e| anyhow::anyhow!("token exchange response decode failed: {e}"))?;

	if let Some(tt) = &parsed.token_type
		&& !tt.eq_ignore_ascii_case("Bearer")
	{
		anyhow::bail!("token exchange returned unsupported token_type: {tt}");
	}

	trace!("token exchange succeeded for audience={}", auth.audience);
	Ok(Some(SecretString::from(parsed.access_token)))
}
