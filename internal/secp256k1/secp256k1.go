// Package secp256k1 是 channels 唯一的签名、验签和长期密钥 ECDH 实现。
package secp256k1

import (
	"bytes"
	"crypto/sha256"

	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	curve "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// PublicKeyFromPrivate 从长期私钥推导压缩公钥。
func PublicKeyFromPrivate(privateKey encoding.PrivateKey) (encoding.PublicKey, error) {
	keyBytes := privateKey.Bytes()
	defer clearBytes(keyBytes)
	if _, err := encoding.NewPrivateKey(keyBytes); err != nil {
		return encoding.PublicKey{}, err
	}
	key := curve.PrivKeyFromBytes(keyBytes)
	defer key.Zero()
	return encoding.NewPublicKeyFromBytes(key.PubKey().SerializeCompressed())
}

// Sign 对已 SHA-256 的签名输入生成 RFC 6979、strict DER、low-S 签名。
func Sign(privateKey encoding.PrivateKey, digest [32]byte) (encoding.Signature, error) {
	keyBytes := privateKey.Bytes()
	defer clearBytes(keyBytes)
	if _, err := encoding.NewPrivateKey(keyBytes); err != nil {
		return encoding.Signature{}, err
	}
	key := curve.PrivKeyFromBytes(keyBytes)
	defer key.Zero()
	signature := ecdsa.Sign(key, digest[:])
	return encoding.NewSignatureFromDER(signature.Serialize())
}

// Verify 严格验证 DER、low-S、r/s 范围和 secp256k1 ECDSA 签名。
func Verify(publicKey encoding.PublicKey, digest [32]byte, signature encoding.Signature) error {
	pub, err := curve.ParsePubKey(publicKey.Bytes())
	if err != nil {
		return protocolerror.New(protocolerror.InvalidSignature, "签名公钥不是有效曲线点")
	}
	parsed, err := ecdsa.ParseDERSignature(signature.DER())
	if err != nil {
		return protocolerror.New(protocolerror.InvalidSignature, "签名不是 strict DER")
	}
	sValue := parsed.S()
	if sValue.IsOverHalfOrder() {
		return protocolerror.New(protocolerror.InvalidSignature, "签名使用 high-S")
	}
	if !bytes.Equal(parsed.Serialize(), signature.DER()) {
		return protocolerror.New(protocolerror.InvalidSignature, "签名 DER 不是唯一规范编码")
	}
	if !parsed.Verify(digest[:], pub) {
		return protocolerror.New(protocolerror.InvalidSignature, "签名验签失败")
	}
	return nil
}

// ECDH 返回 secp256k1 共享点 X 坐标的 32 字节大端编码。
func ECDH(privateKey encoding.PrivateKey, publicKey encoding.PublicKey) ([]byte, error) {
	privateBytes := privateKey.Bytes()
	defer clearBytes(privateBytes)
	if _, err := encoding.NewPrivateKey(privateBytes); err != nil {
		return nil, err
	}
	private := curve.PrivKeyFromBytes(privateBytes)
	defer private.Zero()
	public, err := curve.ParsePubKey(publicKey.Bytes())
	if err != nil {
		return nil, protocolerror.New(protocolerror.InvalidPublicKey, "ECDH 对端公钥无效")
	}
	shared := curve.GenerateSharedSecret(private, public)
	result := append([]byte(nil), shared...)
	clearBytes(shared)
	return result, nil
}

// SHA256 对签名、摘要和测试向量统一使用一次 SHA-256。
func SHA256(input []byte) [32]byte { return sha256.Sum256(input) }

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
