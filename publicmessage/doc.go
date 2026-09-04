// Package publicmessage implements bsv8.public-message.v1 for arbitrary exact
// public channels.
//
// The channel is supplied out of band to ParseAndVerify and is included in the
// signature logic object, while the wire JSON contains only from_public_key,
// message_id, issued_at_ms, expires_at_ms, body, and signature. Body is an
// arbitrary strict JSON value bounded by the shared JCS resource limits.
//
// VerifiedMessage keeps a defensive snapshot. Use Body or SignedMessage to
// obtain copies when passing verified data to application code.
package publicmessage
