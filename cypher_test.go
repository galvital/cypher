package cypher_test

import (
	"testing"

	"github.com/metagate-io/capdirect/cypher"
	"github.com/stretchr/testify/assert"
)

const (
	message = "no guts no glory, bitch."
)

func TestEncryptDecrypt(t *testing.T) {
	privKey, pubKey := cypher.GenerateKeyPair()

	// encrypt
	payload, err := cypher.Encrypt([]byte(message), pubKey)
	assert.Nil(t, err, "encrypt error")
	assert.NotEqual(t, message, string(payload), "payload should not be identical to the message")

	// decrypt
	msg, err := cypher.Decrypt(payload, privKey)
	assert.Nil(t, err, "decrypt error")
	assert.Equal(t, string(msg), message, "decrypted value is different from original value")
}

func TestSignature(t *testing.T) {
	privKey, pubKey := cypher.GenerateKeyPair()

	// sign
	signature, err := cypher.Sign([]byte(message), privKey)
	assert.Nil(t, err, "sign error")
	assert.NotEqual(t, message, string(signature), "signature should not be identical to the message")

	// verify
	isValid := cypher.VerifySignature([]byte(message), signature, pubKey)
	assert.True(t, isValid, "signature is invalid")
}

// TestEndToEnd tests EncryptAndSign and DecryptAndVerify
func TestEndToEnd(t *testing.T) {
	privKey, pubKey := cypher.GenerateKeyPair()

	// encrypt and sign
	payload, signature, err := cypher.EncryptAndSign([]byte(message), privKey, pubKey)
	assert.Nil(t, err, "encrypt and sign error")

	// decrypt and verify
	msg, err := cypher.DecryptAndVerify(payload, signature, privKey, pubKey)
	assert.Nil(t, err, "decrypt and verify failed")
	assert.Equal(t, message, string(msg), "decrypted value is different from original value")
}
