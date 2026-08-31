// Package cryptobox 提供统一 HKDF-SHA256 和 AES-256-GCM 实现。
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
)

// DeriveKey 使用 HKDF-SHA256 从 ECDH 共享秘密派生 32 字节消息密钥。
func DeriveKey(sharedSecret, salt, info []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, salt, string(info), 32)
	if err != nil {
		return nil, protocolerror.Wrap(protocolerror.OpenFailed, "HKDF 派生失败", err)
	}
	return key, nil
}

// Encrypt 使用 AES-256-GCM 加密明文，并返回 ciphertext || 16-byte tag。
func Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, protocolerror.Wrap(protocolerror.InvalidEnvelope, "AES-256 密钥长度错误", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, protocolerror.Wrap(protocolerror.InvalidEnvelope, "AES-GCM 初始化失败", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, protocolerror.New(protocolerror.InvalidEnvelope, "nonce 必须是 12 字节")
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// Decrypt 验证 AES-GCM tag 后解密，失败统一归类为 OPEN_FAILED。
func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() || len(ciphertext) < gcm.Overhead() {
		return nil, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	return plaintext, nil
}

// Clear 尽力清零可控的中间秘密。
func Clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
