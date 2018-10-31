package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// RsaIdentity is just a small struct that clearly differentiates between the private and public key of an RSA keypair
type RsaIdentity struct {
	public *rsa.PublicKey
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
// Sign creates a signature of the message. In addition, it returns a hash.
// The combination of the two can be used to check whether or not the message is created using
// a particular private key (see r.VerifySignature)
func (r *RsaIdentity) Sign(message []byte) ([]byte, []byte, error) {
	var opts rsa.PSSOptions // Probabilistic Signature Scheme
	opts.SaltLength = rsa.PSSSaltLengthAuto
	pssHash := crypto.SHA256.New()
	pssHash.Write(message)
	hashed := pssHash.Sum(nil)

	signed, err := rsa.SignPSS(rand.Reader, r.private, crypto.SHA256, hashed, &opts)

	return signed, hashed, err
}

// VerifySignature checks if the signature is related to the RSA key's from the sender
func (r *RsaIdentity) VerifySignature(sig []byte, hash []byte, pk *rsa.PublicKey) error {
	var opts rsa.PSSOptions // Probabilistic Signature Scheme
	opts.SaltLength = rsa.PSSSaltLengthAuto
	return rsa.VerifyPSS(pk, crypto.SHA256, hash, sig, &opts)
}

// Encrypt's the message using EncryptOAEP which encrypts the given message with RSA-OAEP.
// https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
// Returns the encrypted message and an error.
func (r *RsaIdentity) Encrypt(message []byte, receiverKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	return rsa.EncryptOAEP(hash, rand.Reader, receiverKey, message, label)
}

// Decrypt a message using your private key.
// A received message should be encrypted using the receivers public key.
func (r *RsaIdentity) Decrypt(message []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, r.private, message, label)
}