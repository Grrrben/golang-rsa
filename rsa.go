package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// RsaIdentity is just a small struct that clearly differentiates between the private and public key of an RSA keypair
type RsaIdentity struct {
	public  *rsa.PublicKey
	private *rsa.PrivateKey
}

// NewRsaIdentity returns a new identity with random keys
func NewRsaIdentity() (*RsaIdentity, error) {
	identity := new(RsaIdentity)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return identity, err
	}

	identity.private = priv
	identity.public = &priv.PublicKey
	return identity, nil
}

// Sign returns a signature made by combining the message and the signers private key
// With the r.Verify function, the
func (r *RsaIdentity) Sign(msg []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, r.private, crypto.SHA256, r.getHashSum(msg))
}

func (r *RsaIdentity) Verify(msg []byte, sig []byte, pk *rsa.PublicKey) error {
	h := sha256.New()
	h.Write(msg)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pk, crypto.SHA256, d, sig)
}

// Encrypt's the message using EncryptOAEP which encrypts the given message with RSA-OAEP.
// https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
// Returns the encrypted message and an error.
func (r *RsaIdentity) Encrypt(msg []byte, key *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	return rsa.EncryptOAEP(hash, rand.Reader, key, msg, label)
}

// Decrypt a message using your private key.
// A received message should be encrypted using the receivers public key.
func (r *RsaIdentity) Decrypt(msg []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, r.private, msg, label)
}

func (r *RsaIdentity) getHashSum(msg []byte) []byte {
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
}
