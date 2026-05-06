use ::http::Uri;
use ::http::header::{ACCEPT, CONTENT_TYPE};
use anyhow::anyhow;
use futures::StreamExt;
use headers::HeaderMapExt;
use rmcp::model::{
	ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcRequest, ServerJsonRpcMessage,
};
use rmcp::transport::common::http_header::{
	EVENT_STREAM_MIME_TYPE, HEADER_SESSION_ID, JSON_MIME_TYPE,
};
use sse_stream::SseStream;

use crate::client::ResolvedDestination;
use crate::http::Request;
use crate::mcp::ClientError;
use crate::mcp::streamablehttp::StreamableHttpPostResponse;
use crate::mcp::upstream::IncomingRequestContext;
use crate::*;

const RECOVERY_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);
const RECOVERY_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug)]
struct Backoff {
	failures: u32,
	next_retry: tokio::time::Instant,
}

/// Per-target retry backoff for `tools/list` recovery, so a permanently-broken
/// streamable target is not re-handshaked on every request.
#[derive(Clone, Debug, Default)]
struct RecoveryBackoff(AtomicOption<Backoff>);

impl RecoveryBackoff {
	fn due(&self) -> bool {
		self
			.0
			.load()
			.as_deref()
			.is_none_or(|b| tokio::time::Instant::now() >= b.next_retry)
	}

	fn record_failure(&self) {
		let failures = self.0.load().as_deref().map_or(0, |b| b.failures) + 1;
		// The first failure retries immediately so a transient failure (e.g. auth not
		// yet granted) recovers on the next request; repeated failures back off.
		let delay = if failures < 2 {
			std::time::Duration::ZERO
		} else {
			RECOVERY_BACKOFF_BASE
				.saturating_mul(1u32 << (failures - 2).min(5))
				.min(RECOVERY_BACKOFF_MAX)
		};
		self.0.store(Some(Arc::new(Backoff {
			failures,
			next_retry: tokio::time::Instant::now() + delay,
		})));
	}

	fn reset(&self) {
		self.0.store(None);
	}
}

#[derive(Clone, Debug)]
pub struct Client {
	http_client: super::McpHttpClient,
	uri: Uri,
	session_id: AtomicOption<String>,
	recovery_backoff: RecoveryBackoff,
}

impl Client {
	pub fn new(http_client: super::McpHttpClient, path: Strng) -> anyhow::Result<Self> {
		let hp = http_client.backend().hostport();
		Ok(Self {
			http_client,
			uri: ("http://".to_string() + &hp + path.as_str()).parse()?,
			session_id: Default::default(),
			recovery_backoff: Default::default(),
		})
	}

	/// Whether a failed target is eligible for another recovery handshake now.
	pub fn recovery_due(&self) -> bool {
		self.recovery_backoff.due()
	}

	/// Record a failed recovery, pushing the next attempt out exponentially.
	pub fn record_recovery_failure(&self) {
		self.recovery_backoff.record_failure();
	}

	/// Clear backoff after a successful recovery.
	pub fn reset_recovery_backoff(&self) {
		self.recovery_backoff.reset();
	}

	pub fn get_session_state(&self) -> http::sessionpersistence::MCPSession {
		let session_id = self.session_id.load().clone();
		let backend = self.http_client.pinned_backend();
		http::sessionpersistence::MCPSession {
			target_name: Some(self.http_client.target_name().to_string()),
			session: session_id.map(|s| s.to_string()),
			backend,
		}
	}

	pub fn set_session_id(&self, s: Option<&str>, pinned: Option<SocketAddr>) {
		self.session_id.store(s.map(|s| Arc::new(s.to_string())));
		if let Some(pinned) = pinned {
			self.http_client.pin_backend(ResolvedDestination(pinned));
		}
	}

	pub fn has_session_id(&self) -> bool {
		self.session_id.load().is_some()
	}

	pub async fn send_request(
		&self,
		req: JsonRpcRequest<ClientRequest>,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let message = ClientJsonRpcMessage::Request(req);
		self.send_message(message, ctx).await
	}
	pub async fn send_notification(
		&self,
		req: ClientNotification,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let message = ClientJsonRpcMessage::notification(req);
		self.send_message(message, ctx).await
	}
	async fn send_message(
		&self,
		message: ClientJsonRpcMessage,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let body = serde_json::to_vec(&message).map_err(ClientError::new)?;

		let mut req = ::http::Request::builder()
			.uri(&self.uri)
			.method(http::Method::POST)
			.header(CONTENT_TYPE, "application/json")
			.header(ACCEPT, [EVENT_STREAM_MIME_TYPE, JSON_MIME_TYPE].join(", "))
			.body(body.into())
			.map_err(ClientError::new)?;

		self.maybe_insert_session_id(&mut req)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;

		let resp = self.http_client.call(req).await?;

		// MCP spec has 202 only but some servers in the wild return 204. This is close enough for us to massage it.
		if resp.status() == http::StatusCode::ACCEPTED || resp.status() == http::StatusCode::NO_CONTENT
		{
			return Ok(StreamableHttpPostResponse::Accepted);
		}

		if !resp.status().is_success() {
			return Err(ClientError::Status(Box::new(resp)));
		}

		let content_type = resp.headers().get(CONTENT_TYPE);
		let session_id = resp
			.headers()
			.get(HEADER_SESSION_ID)
			.and_then(|v| v.to_str().ok())
			.map(|s| s.to_string());

		match content_type {
			Some(ct) if ct.as_bytes().starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) => {
				let content_encoding = resp.headers().typed_get::<headers::ContentEncoding>();
				let (body, _encoding) =
					crate::http::compression::decompress_body(resp.into_body(), content_encoding.as_ref())
						.map_err(ClientError::new)?;
				let event_stream = SseStream::from_byte_stream(body.into_data_stream()).boxed();
				Ok(StreamableHttpPostResponse::Sse(event_stream, session_id))
			},
			Some(ct) if ct.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()) => {
				let lim = crate::http::response_buffer_limit(&resp);
				let content_encoding = resp.headers().typed_get::<headers::ContentEncoding>();
				let body_bytes = crate::http::compression::to_bytes_with_decompression(
					resp.into_body(),
					content_encoding.as_ref(),
					lim,
				)
				.await
				.map_err(ClientError::new)?
				.1;
				let message: Option<ServerJsonRpcMessage> =
					serde_json::from_slice(&body_bytes).map_err(ClientError::new)?;
				match message {
					Some(msg) => Ok(StreamableHttpPostResponse::Json(msg, session_id)),
					None => Ok(StreamableHttpPostResponse::Accepted),
				}
			},
			_ => Err(ClientError::new(anyhow!(
				"unexpected content type: {:?}",
				content_type
			))),
		}
	}
	pub async fn send_delete(
		&self,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let mut req = ::http::Request::builder()
			.uri(&self.uri)
			.method(http::Method::DELETE)
			.body(crate::http::Body::empty())
			.map_err(ClientError::new)?;

		self.maybe_insert_session_id(&mut req)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;

		let resp = self.http_client.call(req).await?;

		if !resp.status().is_success() {
			return Err(ClientError::Status(Box::new(resp)));
		}
		Ok(StreamableHttpPostResponse::Accepted)
	}
	pub async fn get_event_stream(
		&self,
		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let mut req = ::http::Request::builder()
			.uri(&self.uri)
			.method(http::Method::GET)
			.header(ACCEPT, EVENT_STREAM_MIME_TYPE)
			.body(crate::http::Body::empty())
			.map_err(ClientError::new)?;

		self.maybe_insert_session_id(&mut req)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;

		let resp = self.http_client.call(req).await?;

		if !resp.status().is_success() {
			return Err(ClientError::Status(Box::new(resp)));
		}

		let content_type = resp.headers().get(CONTENT_TYPE);
		let session_id = resp
			.headers()
			.get(HEADER_SESSION_ID)
			.and_then(|v| v.to_str().ok())
			.map(|s| s.to_string());
		match content_type {
			Some(ct) if ct.as_bytes().starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) => {
				let content_encoding = resp.headers().typed_get::<headers::ContentEncoding>();
				let (body, _encoding) =
					crate::http::compression::decompress_body(resp.into_body(), content_encoding.as_ref())
						.map_err(ClientError::new)?;
				let event_stream = SseStream::from_byte_stream(body.into_data_stream()).boxed();
				Ok(StreamableHttpPostResponse::Sse(event_stream, session_id))
			},
			_ => Err(ClientError::new(anyhow!(
				"unexpected content type for GET streams: {:?}",
				content_type
			))),
		}
	}

	fn maybe_insert_session_id(&self, req: &mut Request) -> Result<(), ClientError> {
		if let Some(session_id) = self.session_id.load().clone() {
			req.headers_mut().insert(
				HEADER_SESSION_ID,
				session_id.as_ref().parse().map_err(ClientError::new)?,
			);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;

	#[tokio::test(start_paused = true)]
	async fn recovery_backoff_grows_and_resets() {
		let b = RecoveryBackoff::default();
		assert!(b.due(), "a fresh target is immediately eligible");

		// First failure keeps the target immediately eligible (fast transient recovery).
		b.record_failure();
		assert!(b.due(), "first failure still allows an immediate retry");

		// Second consecutive failure backs off by the base window.
		b.record_failure();
		assert!(
			!b.due(),
			"second failure is not eligible within the base window"
		);
		tokio::time::advance(Duration::from_secs(1)).await;
		assert!(b.due(), "eligible once the base window elapses");

		// Third consecutive failure backs off further (2s, not 1s).
		b.record_failure();
		tokio::time::advance(Duration::from_secs(1)).await;
		assert!(!b.due(), "third window is longer than the base");
		tokio::time::advance(Duration::from_secs(1)).await;
		assert!(b.due(), "eligible once the longer window elapses");

		b.reset();
		assert!(b.due(), "reset clears the backoff");
	}
}
