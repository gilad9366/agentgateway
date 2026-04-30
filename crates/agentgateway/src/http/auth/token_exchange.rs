use std::sync::Arc;
use std::time::{Duration, Instant};

use ::http::HeaderValue;
use ::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use quick_cache::sync::Cache;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tracing::trace;
use url::form_urlencoded;

use crate::client::Client;
use crate::http::Body;
use crate::json;
#[cfg(feature = "schema")]
use crate::serdes::FileOrInline;
use crate::serdes::{deser_key_from_file, schema, ser_redact};
use crate::{apply, http};

#[apply(schema!)]
pub struct TokenExchangeAuth {
	/// RFC 8693 token endpoint URL.
	pub token_endpoint: String,
	/// `audience` parameter identifying the upstream being called.
	pub audience: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub client: Option<ClientCredentials>,
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	cache: TokenExchangeCache,
}

#[apply(schema!)]
pub struct ClientCredentials {
	pub client_id: String,
	#[cfg_attr(feature = "schema", schemars(with = "FileOrInline"))]
	#[serde(
		serialize_with = "ser_redact",
		deserialize_with = "deser_key_from_file"
	)]
	pub client_secret: SecretString,
}

impl TokenExchangeAuth {
	pub fn new(token_endpoint: String, audience: String, client: Option<ClientCredentials>) -> Self {
		Self {
			token_endpoint,
			audience,
			client,
			cache: TokenExchangeCache::default(),
		}
	}
}

impl ClientCredentials {
	fn basic_header(&self) -> anyhow::Result<HeaderValue> {
		let id: String = form_urlencoded::byte_serialize(self.client_id.as_bytes()).collect();
		let secret: String =
			form_urlencoded::byte_serialize(self.client_secret.expose_secret().as_bytes()).collect();
		let encoded = BASE64_STANDARD.encode(format!("{id}:{secret}"));
		let mut hv = HeaderValue::from_str(&format!("Basic {encoded}"))?;
		hv.set_sensitive(true);
		Ok(hv)
	}
}

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub(super) const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub(super) const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

const CACHE_SAFETY_MARGIN: Duration = Duration::from_secs(30);
const CACHE_CAPACITY: usize = 1024;

#[derive(Debug, Deserialize)]
struct TokenResponse {
	access_token: String,
	issued_token_type: String,
	token_type: String,
	#[serde(default)]
	expires_in: Option<u64>,
}

#[derive(Clone)]
struct CachedToken {
	access_token: SecretString,
	expires_at: Instant,
}

#[derive(Clone)]
pub struct TokenExchangeCache(Arc<Cache<String, CachedToken>>);

impl Default for TokenExchangeCache {
	fn default() -> Self {
		Self(Arc::new(Cache::new(CACHE_CAPACITY)))
	}
}

impl std::fmt::Debug for TokenExchangeCache {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("TokenExchangeCache")
	}
}

pub(crate) async fn fetch_token(
	client: &Client,
	auth: &TokenExchangeAuth,
	subject_token: &str,
	subject_token_type: &str,
) -> anyhow::Result<SecretString> {
	let cache = &auth.cache.0;
	if let Some(cached) = cache.get(subject_token) {
		if cached.expires_at > Instant::now() {
			trace!("token exchange cache hit for audience={}", auth.audience);
			return Ok(cached.access_token);
		}
		cache.remove(subject_token);
	}

	let guard = match cache.get_value_or_guard_async(subject_token).await {
		Ok(cached) => return Ok(cached.access_token),
		Err(guard) => guard,
	};

	let body = form_urlencoded::Serializer::new(String::new())
		.append_pair("grant_type", GRANT_TYPE)
		.append_pair("subject_token", subject_token)
		.append_pair("subject_token_type", subject_token_type)
		.append_pair("audience", &auth.audience)
		.finish();

	let mut builder = ::http::Request::builder()
		.method(::http::Method::POST)
		.uri(&auth.token_endpoint)
		.header(CONTENT_TYPE, "application/x-www-form-urlencoded")
		.header(ACCEPT, "application/json");
	if let Some(creds) = &auth.client {
		builder = builder.header(AUTHORIZATION, creds.basic_header()?);
	}
	let req = builder.body(Body::from(body.into_bytes()))?;

	let resp = client
		.simple_call(req)
		.await
		.map_err(|e| anyhow::anyhow!("token exchange request failed: {e}"))?;

	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("token exchange returned status: {status}");
	}

	let limit = http::response_buffer_limit(&resp);
	let parsed: TokenResponse = json::from_body_with_limit(resp.into_body(), limit)
		.await
		.map_err(|e| anyhow::anyhow!("token exchange response decode failed: {e}"))?;

	if !parsed.token_type.eq_ignore_ascii_case("Bearer") {
		anyhow::bail!(
			"token exchange returned unsupported token_type: {}",
			parsed.token_type
		);
	}

	if parsed.issued_token_type != TOKEN_TYPE_ACCESS && parsed.issued_token_type != TOKEN_TYPE_JWT {
		anyhow::bail!(
			"token exchange returned unusable issued_token_type: {}",
			parsed.issued_token_type
		);
	}

	let access_token = SecretString::from(parsed.access_token);

	if let Some(secs) = parsed.expires_in
		&& secs > CACHE_SAFETY_MARGIN.as_secs()
	{
		let ttl = Duration::from_secs(secs) - CACHE_SAFETY_MARGIN;
		let _ = guard.insert(CachedToken {
			access_token: access_token.clone(),
			expires_at: Instant::now() + ttl,
		});
	}

	trace!("token exchange succeeded for audience={}", auth.audience);
	Ok(access_token)
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use hickory_resolver::config::{ResolverConfig, ResolverOpts};
	use serde_json::json;
	use wiremock::matchers::{method, path};
	use wiremock::{Mock, MockServer, ResponseTemplate};

	use super::*;
	use crate::client;

	fn test_client() -> client::Client {
		client::Client::new(
			&client::Config {
				resolver_cfg: ResolverConfig::default(),
				resolver_opts: ResolverOpts::default(),
			},
			None,
			Default::default(),
			None,
		)
	}

	fn creds() -> ClientCredentials {
		ClientCredentials {
			client_id: "cid".into(),
			client_secret: SecretString::from("csecret"),
		}
	}

	fn token_body() -> serde_json::Value {
		json!({
			"access_token": "upstream-token",
			"token_type": "Bearer",
			"issued_token_type": TOKEN_TYPE_ACCESS,
			"expires_in": 3600,
		})
	}

	async fn mock_token_endpoint(body: ResponseTemplate) -> MockServer {
		let mock = MockServer::start().await;
		Mock::given(method("POST"))
			.and(path("/token"))
			.respond_with(body)
			.mount(&mock)
			.await;
		mock
	}

	fn auth(endpoint: String, client: Option<ClientCredentials>) -> TokenExchangeAuth {
		TokenExchangeAuth::new(endpoint, "https://upstream.example".into(), client)
	}

	#[test]
	fn basic_header_is_sensitive_base64() {
		let hv = creds().basic_header().unwrap();
		assert!(hv.is_sensitive());
		assert_eq!(
			hv.to_str().unwrap(),
			format!("Basic {}", BASE64_STANDARD.encode("cid:csecret"))
		);
	}

	#[tokio::test]
	async fn sends_basic_auth_and_form_params() {
		let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
		let a = auth(format!("{}/token", mock.uri()), Some(creds()));

		let tok = fetch_token(&test_client(), &a, "subj-jwt", TOKEN_TYPE_JWT)
			.await
			.expect("exchange succeeds");
		assert_eq!(tok.expose_secret(), "upstream-token");

		let req = &mock.received_requests().await.unwrap()[0];
		assert_eq!(
			req.headers.get("authorization").unwrap().to_str().unwrap(),
			format!("Basic {}", BASE64_STANDARD.encode("cid:csecret"))
		);
		let body = String::from_utf8(req.body.clone()).unwrap();
		let pairs: HashMap<_, _> = form_urlencoded::parse(body.as_bytes())
			.into_owned()
			.collect();
		assert_eq!(pairs["grant_type"], GRANT_TYPE);
		assert_eq!(pairs["subject_token"], "subj-jwt");
		assert_eq!(pairs["subject_token_type"], TOKEN_TYPE_JWT);
		assert_eq!(pairs["audience"], "https://upstream.example");
	}

	#[tokio::test]
	async fn public_client_sends_no_authorization() {
		let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
		let a = auth(format!("{}/token", mock.uri()), None);

		fetch_token(&test_client(), &a, "subj", TOKEN_TYPE_JWT)
			.await
			.unwrap();
		let req = &mock.received_requests().await.unwrap()[0];
		assert!(req.headers.get("authorization").is_none());
	}

	#[tokio::test]
	async fn fails_closed_on_client_error() {
		let mock = mock_token_endpoint(ResponseTemplate::new(401)).await;
		let a = auth(format!("{}/token", mock.uri()), None);

		assert!(
			fetch_token(&test_client(), &a, "subj", TOKEN_TYPE_JWT)
				.await
				.is_err()
		);
	}

	#[tokio::test]
	async fn rejects_unusable_issued_token_type() {
		let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
			"access_token": "t",
			"token_type": "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:saml2",
		})))
		.await;
		let a = auth(format!("{}/token", mock.uri()), None);

		assert!(
			fetch_token(&test_client(), &a, "subj", TOKEN_TYPE_JWT)
				.await
				.is_err()
		);
	}

	#[tokio::test]
	async fn caches_per_subject() {
		let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
		let a = auth(format!("{}/token", mock.uri()), None);
		let client = test_client();

		let t1 = fetch_token(&client, &a, "subj", TOKEN_TYPE_JWT)
			.await
			.unwrap();
		let t2 = fetch_token(&client, &a, "subj", TOKEN_TYPE_JWT)
			.await
			.unwrap();
		assert_eq!(t1.expose_secret(), t2.expose_secret());
		assert_eq!(mock.received_requests().await.unwrap().len(), 1);
	}
}
