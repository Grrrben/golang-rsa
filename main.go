package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
)

// RsaIdentity is just a small struct that clearly differentiates between the private and public key of an RSA keypair
type RsaIdentity struct {
	public *rsa.PublicKey
	private *rsa.PrivateKey
}

// SignMessage creates a signature of the message. In addition, it returns a hash.
// The combination of the two can be used to check whether or not the message is created using
// a particular private key (see r.VerifySignature)
func (r *RsaIdentity) SignMessage(message []byte) ([]byte, []byte, error) {
	var opts rsa.PSSOptions // Probabilistic Signature Scheme
	opts.SaltLength = rsa.PSSSaltLengthAuto
	pssHash := crypto.SHA256.New()
	pssHash.Write(message)
	hashed := pssHash.Sum(nil)

	signed, err := rsa.SignPSS(rand.Reader, r.private, crypto.SHA256, hashed, &opts)

	return signed, hashed, err
}


func (r *RsaIdentity) VerifySignature(signature []byte, hashedMessage []byte, publicKey *rsa.PublicKey) error {
	var opts rsa.PSSOptions // Probabilistic Signature Scheme
	opts.SaltLength = rsa.PSSSaltLengthAuto
	return rsa.VerifyPSS(publicKey, crypto.SHA256, hashedMessage, signature, &opts)
}

// Encrypt's the message using EncryptOAEP which encrypts the given message with RSA-OAEP.
// https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
func (r *RsaIdentity) Encrypt(message []byte, receiverKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	return rsa.EncryptOAEP(hash, rand.Reader, receiverKey, message, label)
}

// Decrypt a message using your private key. A received message should be encrypted using the receivers public key.
func (r *RsaIdentity) Decrypt(message []byte) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, r.private, message, label)
}

func NewIdentity() (*RsaIdentity, error) {
	identity := new(RsaIdentity)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return identity, err
	}

	identity.private = priv
	identity.public = &priv.PublicKey
	return identity, nil
}

func main() {

	// we need two persons talking to each other
	henk, err := NewIdentity()

	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

	gerda, err := NewIdentity()

	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

	// A message from Henk to Gerda,
	// note that the message is a byte array, not just a string.
	message := []byte("My vote is on that blond haired Wilder's guy")

	// Lets encrypt it, we want to sent it to Gerda, thus, we need her public key.
	receiverKey := gerda.public
	encryptedMessage, err := henk.Encrypt(message, receiverKey)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Henk signs the message with his private key. This will show the recipient
	// proof that this message is indeed from Henk
	signature, hashedMessage,  err := henk.SignMessage(message)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Decrypt Message
	plainTextMessage, err := gerda.Decrypt(encryptedMessage)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("OAEP decrypted [%x] to \n[%s]\n", encryptedMessage, plainTextMessage)

	// Verify Signature
	err = gerda.VerifySignature(signature, hashedMessage, henk.public)

	if err != nil {
		fmt.Println("Who are U? Verify Signature failed")
		os.Exit(1)
	} else {
		fmt.Println("Verify Signature successful")
	}

}