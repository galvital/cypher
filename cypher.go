// main library entry point
package cypher

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/pkg/errors"

	"github.com/labstack/gommon/log"
)

// GenerateKeyPair returns new private and public keys.
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return privKey, &privKey.PublicKey
}

// Encrypt returns a cypher of a message.
func Encrypt(msg []byte, key *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	payload, err := rsa.EncryptOAEP(hash, rand.Reader, key, msg, label)
	if err != nil {
		return nil, errors.Wrap(err, ErrUnableToEncrypt)
	}
	return payload, nil
}

// Decrypt returns a message decrypted from a cypher.
func Decrypt(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	msg, err := rsa.DecryptOAEP(hash, rand.Reader, key, payload, label)
	if err != nil {
		return nil, errors.Wrap(err, ErrUnableToDecrypt)
	}
	return msg, nil
}

// Sign returns a signature of a message-hash.
// First the message is hashes (sha256) in order to shrink it,
// then the result hash is being signed with the private key.
func Sign(msg []byte, key *rsa.PrivateKey) ([]byte, error) {

	// get a sha256 hash of the message.
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // todo- is this good enough?
	pssmsg := msg
	hash := crypto.SHA256
	pssh := hash.New()
	pssh.Write(pssmsg)
	hashed := pssh.Sum(nil)

	// sign hash with private key.
	signature, err := rsa.SignPSS(rand.Reader, key, hash, hashed, &opts)
	if err != nil {
		return nil, errors.Wrap(err, ErrUnableToSign)
	}
	return signature, nil
}

// VerifySignature returns true if the given
// message and signature are valid, else false.
func VerifySignature(msg, sig []byte, key *rsa.PublicKey) bool {
	// get a sha256 hash of the message.
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	pssmsg := msg
	hash := crypto.SHA256
	pssh := hash.New()
	pssh.Write(pssmsg)
	hashed := pssh.Sum(nil)
	err := rsa.VerifyPSS(key, crypto.SHA256, hashed, sig, &opts)
	if err != nil {
		return false
	}
	return true
}

// EncryptAndSign returns a cypher and a signature of a message.
func EncryptAndSign(msg []byte, privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) (payload, signature []byte, err error) {
	pl, err := Encrypt(msg, pubKey)
	if err != nil {
		return nil, nil, err
	}
	sig, err := Sign(msg, privKey)
	if err != nil {
		return nil, nil, err
	}
	return pl, sig, nil
}

// DecryptAndVerify attempts to decrypt a cypher and verify
// it's signature, returns error if fails or invalid signature.
func DecryptAndVerify(payload, signature []byte, privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) ([]byte, error) {

	// decrypt
	msg, err := Decrypt(payload, privKey)
	if err != nil {
		return nil, err
	}

	// verify
	if !VerifySignature(msg, signature, pubKey) {
		return nil, errors.New(ErrInvalidSignature)
	}

	return msg, nil
}

var ErrUnableToEncrypt = "UnableToEncrypt"
var ErrUnableToDecrypt = "UnableToDecrypt"
var ErrUnableToSign = "UnableToSign"
var ErrInvalidSignature = "InvalidSignature"
