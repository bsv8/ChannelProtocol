package publicmessage_test

import (
	"fmt"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/publicmessage"
)

func Example() {
	privateBytes := make([]byte, 32)
	privateBytes[31] = 1
	privateKey, _ := channels.ParsePrivateKey(privateBytes)
	publicKey, _ := channels.PublicKeyFromPrivate(privateKey)
	messageID, _ := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	signed, _ := publicmessage.Sign(publicmessage.UnsignedMessage{
		Channel:       "bsv8.public.example.v1",
		FromPublicKey: publicKey,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          map[string]any{"kind": "demo", "value": 1},
	}, privateKey)
	wire, _ := publicmessage.Marshal(signed)
	verified, _ := publicmessage.ParseAndVerify("bsv8.public.example.v1", wire, 1500)
	fmt.Println(verified.IsVerified())
	// Output: true
}
