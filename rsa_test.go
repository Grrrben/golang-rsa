package main

import (
	"bytes"
	"testing"
)

func TestNewRsaIdentity(t *testing.T) {
	henk, err := NewRsaIdentity()

	if err != nil {
		t.Errorf("Unable to create identity for Henk; %s", err)
	}

	pkSize := henk.public.Size()

	if pkSize != 256 {
		t.Errorf("Unexpected pubic key size for Henk; expected %d got %d", 256, pkSize)
	}
}

func TestSignature(t *testing.T) {
	henk, err := NewRsaIdentity()

	if err != nil {
		t.Errorf("Unable to create identity for Henk; %s", err)
	}

	// A message from Henk to Ingrid,
	// note that the message is a byte array, not just a string.
	msg := []byte("Is dit kunst of kan het weg?")
	// Henk signs the message with his private key. This will show the recipient
	// proof that this message is indeed from Henk
	sig, hash, err := henk.Sign(msg)

	if err != nil {
		t.Errorf("Unable to sign the message; %s", err)
	}

	// check if the signature is from Henk, proving that the message is indeed sent by Henk.
	err = henk.VerifySignature(sig, hash, henk.public)

	if err != nil {
		t.Errorf("Signature is not from Henk...; %s", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	henk, err := NewRsaIdentity()

	if err != nil {
		t.Errorf("Unable to create identity for Henk; %s", err)
	}

	ingrid, err := NewRsaIdentity()

	if err != nil {
		t.Errorf("Unable to create identity for Ingrid; %s", err)
	}

	// a message from Henk to Ingrid
	msg := []byte("Die uitkeringstrekkers pikken al onze banen in.")
	// Lets encrypt it, we want to sent it to Ingrid, thus, we need her public key.
	encryptedMessage, err := henk.Encrypt(msg, ingrid.public)

	if err != nil {
		t.Errorf("Unable to encrypt Henk's message for Ingrid; %s", err)
	}

	// Decrypt Message
	plainTextMessage, err := ingrid.Decrypt(encryptedMessage)

	if  err != nil {
		t.Errorf("Unable to decrypt Henk's message for Ingrid; %s", err)
	}

	if  !bytes.Equal(plainTextMessage[:], msg[:]) {
		t.Error("Unable to decrypt Henk's message for Ingrid; byte arrays are not the same")
	}
}

func TestEncryptDecryptMyself(t *testing.T) {
	// If anyone, even you, encrypts (i.e. “locks”) something with your public-key,
	// only you can decrypt it (i.e. “unlock” it) with your secret, private key.
	henk, err := NewRsaIdentity()

	if err != nil {
		t.Errorf("Unable to create identity for Henk; %s", err)
	}

	// a message from Henk
	msg := []byte("Subsidie, dat is toch iets dat je krijgt als je eigenlijk niet goed genoeg bent?")
	// Lets encrypt it, we want to sent it to Ingrid, thus, we need her public key.
	encryptedMessage, err := henk.Encrypt(msg, henk.public)

	if err != nil {
		t.Errorf("Unable to encrypt Henk's personal message; %s", err)
	}

	// Decrypt Message
	plainTextMessage, err := henk.Decrypt(encryptedMessage)

	if err != nil {
		t.Errorf("Unable to decrypt Henk's personal message; %s", err)
	}

	if !bytes.Equal(plainTextMessage[:], msg[:]) {
		t.Error("Unable to decrypt Henk's personal message; byte arrays are not the same")
	}
}

func TestMyMessage(t *testing.T) {
	// If you encrypt (i.e. “lock”) something with your private key, anyone can decrypt it (i.e. “unlock” it),
	// but this serves as a proof that you encrypted it: it’s “digitally signed” by you.

	// todo
}

