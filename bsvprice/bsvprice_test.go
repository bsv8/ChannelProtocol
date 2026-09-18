package bsvprice_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	channels "github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/bsvprice"
	"github.com/bsv8/ChannelProtocol/publicmessage"
)

func testKey(t *testing.T) (channels.PrivateKey, channels.PublicKey) {
	t.Helper()
	privateKey, err := channels.GeneratePrivateKeyFrom(bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := channels.PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey
}

func testMessage(t *testing.T) (channels.PrivateKey, channels.PublicKey, bsvprice.UnsignedMessage) {
	t.Helper()
	privateKey, publicKey := testKey(t)
	messageID, err := channels.NewMessageID(bytes.NewReader(bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	body, err := bsvprice.NewBody(1000, map[string]map[string]string{
		"gate": {"bsvusdt": "45.1200", "bsvcny": "321.85"},
		"okx":  {"bsvusdt": "45.0900"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey, bsvprice.UnsignedMessage{
		FromPublicKey: publicKey,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          body,
	}
}

func TestSignMarshalParseAndVerify(t *testing.T) {
	privateKey, publicKey, unsigned := testMessage(t)
	signed, err := bsvprice.Sign(unsigned, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := bsvprice.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	const expectedWire = `{"body":{"markets":{"gate":{"bsvcny":"321.85","bsvusdt":"45.1200"},"okx":{"bsvusdt":"45.0900"}},"protocol":"bsv8.bsv-price.v1","snapshot_at_ms":1000},"expires_at_ms":2000,"from_public_key":"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f","issued_at_ms":1000,"message_id":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","signature":"MEQCIF3iRwrJqHm9iBVIbBsp5_tgTANil1ed2Zj9GjdcUyioAiBOr0mkhWwROWoenKE5vq1v6SnCvE7UFnhOMd0sJDRh7g"}`
	if string(wire) != expectedWire {
		t.Fatalf("cross-language wire mismatch: %s", wire)
	}
	if got := signed.SignedDigest().String(); got != "fc19ee6bfbc7c15720da52bacca8cea912c4a2e34b2484755b9f29c7ee844104" {
		t.Fatalf("cross-language digest mismatch: %s", got)
	}
	verified, err := bsvprice.ParseAndVerify(bsvprice.Channel(publicKey), wire)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.IsVerified() {
		t.Fatal("expected verified message")
	}
	if verified.Body().Markets["gate"]["bsvcny"] != "321.85" {
		t.Fatalf("unexpected body: %#v", verified.Body())
	}
	if verified.Digest() != signed.SignedDigest() {
		t.Fatal("digest mismatch")
	}

	copyBody := verified.Body()
	copyBody.Markets["gate"]["bsvusdt"] = "0"
	if verified.Body().Markets["gate"]["bsvusdt"] != "45.1200" {
		t.Fatal("verified body was not defensively copied")
	}
}

func TestChannelAndBodyValidation(t *testing.T) {
	_, publicKey, _ := testMessage(t)
	channel := bsvprice.Channel(publicKey)
	parsed, err := bsvprice.ParseChannel(channel)
	if err != nil || !parsed.Equal(publicKey) {
		t.Fatalf("channel round trip failed: %v", err)
	}
	for _, invalid := range []string{
		"bsvprice.",
		"bsvprice." + publicKey.String()[:65] + "0",
		"price." + publicKey.String(),
	} {
		if _, err := bsvprice.ParseChannel(invalid); err == nil {
			t.Fatalf("expected invalid channel: %q", invalid)
		}
	}
	for _, body := range []bsvprice.BSVPriceBody{
		{Protocol: "old", SnapshotAtMs: 1, Markets: map[string]map[string]string{"gate": {"bsvusdt": "1"}}},
		{Protocol: bsvprice.Protocol, SnapshotAtMs: 1, Markets: map[string]map[string]string{"Gate": {"bsvusdt": "1"}}},
		{Protocol: bsvprice.Protocol, SnapshotAtMs: 1, Markets: map[string]map[string]string{"gate": {"bsvusdt": "1e-3"}}},
	} {
		if err := bsvprice.ValidateBody(body); err == nil {
			t.Fatalf("expected invalid body: %#v", body)
		}
	}
	if _, err := bsvprice.ParseBody(map[string]any{
		"protocol":       bsvprice.Protocol,
		"snapshot_at_ms": float64(1),
		"markets":        map[string]any{"gate": map[string]any{"bsvusdt": 1.0}},
	}); err == nil {
		t.Fatal("expected numeric price to be rejected")
	}
}

func TestIdentifierRejectsPunctuationAsFirstCharacter(t *testing.T) {
	for _, invalid := range []string{".gate", "-gate", "_gate"} {
		marketBody := bsvprice.BSVPriceBody{
			Protocol:     bsvprice.Protocol,
			SnapshotAtMs: 1,
			Markets:      map[string]map[string]string{invalid: {"bsvusdt": "1"}},
		}
		if err := bsvprice.ValidateBody(marketBody); err == nil {
			t.Fatalf("expected invalid market identifier: %q", invalid)
		}

		pairBody := bsvprice.BSVPriceBody{
			Protocol:     bsvprice.Protocol,
			SnapshotAtMs: 1,
			Markets:      map[string]map[string]string{"gate": {invalid: "1"}},
		}
		if err := bsvprice.ValidateBody(pairBody); err == nil {
			t.Fatalf("expected invalid pair identifier: %q", invalid)
		}
	}
}

func TestEmptyMarketsBodyIsValid(t *testing.T) {
	body, err := bsvprice.NewBody(1, map[string]map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if body.Markets == nil || len(body.Markets) != 0 {
		t.Fatalf("expected canonical empty markets map, got %#v", body.Markets)
	}
	parsed, err := bsvprice.ParseBody(map[string]any{
		"protocol":       bsvprice.Protocol,
		"snapshot_at_ms": json.Number("1"),
		"markets":        map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Markets == nil || len(parsed.Markets) != 0 {
		t.Fatalf("expected parsed empty markets map, got %#v", parsed.Markets)
	}
}

func TestChannelAuthorMismatch(t *testing.T) {
	privateKey, author, unsigned := testMessage(t)
	_, other := testKeyForByte(t, 3)
	public, err := publicmessage.Sign(publicmessage.UnsignedMessage{
		Channel:       bsvprice.Channel(other),
		FromPublicKey: author,
		MessageID:     unsigned.MessageID,
		IssuedAtMs:    unsigned.IssuedAtMs,
		ExpiresAtMs:   unsigned.ExpiresAtMs,
		Body: map[string]any{
			"protocol":       bsvprice.Protocol,
			"snapshot_at_ms": unsigned.Body.SnapshotAtMs,
			"markets":        map[string]any{"gate": map[string]any{"bsvusdt": "1"}},
		},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := publicmessage.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bsvprice.ParseAndVerify(bsvprice.Channel(other), wire); !errors.Is(err, channels.ErrIdentityMismatch) {
		t.Fatalf("expected identity mismatch, got %v", err)
	}
}

func testKeyForByte(t *testing.T, value byte) (channels.PrivateKey, channels.PublicKey) {
	t.Helper()
	privateKey, err := channels.GeneratePrivateKeyFrom(bytes.NewReader(bytes.Repeat([]byte{value}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := channels.PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey
}

func TestParseBodyFromJSONNumber(t *testing.T) {
	value := map[string]any{
		"protocol":       bsvprice.Protocol,
		"snapshot_at_ms": json.Number("1000"),
		"markets":        map[string]any{"gate": map[string]any{"bsvusdt": "1.00"}},
	}
	body, err := bsvprice.ParseBody(value)
	if err != nil {
		t.Fatal(err)
	}
	if body.SnapshotAtMs != 1000 || body.Markets["gate"]["bsvusdt"] != "1.00" {
		t.Fatalf("unexpected body: %#v", body)
	}
}
