package channels

import (
	"github.com/bsv8/ChannelProtocol/internal/canonicaljson"
)

func canonicalizeJSON(input []byte) ([]byte, error) {
	return canonicaljson.CanonicalizeJSON(input)
}

func canonicalizeValue(value any) ([]byte, error) {
	return canonicaljson.CanonicalizeValue(value)
}
