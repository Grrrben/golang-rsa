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

func TestEncrypt(t *testing.T) {
	henk, _ := NewRsaIdentity()
	jaap, _ := NewRsaIdentity()
	ingrid, _ := NewRsaIdentity()

	msg := []byte("Arme mensen kunnen niet met geld omgaan: ze geven alles uit aan eten en kleren, " +
		"terwijl rijke mensen het heel verstandig op de bank zetten.")

	// Lets encrypt it using Ingrid's public key.
	henksMessage, err := henk.Encrypt(msg, ingrid.public)
	if err != nil {
		t.Errorf("Unable to encrypt Henk's message for Ingrid; %s", err)
	}

	jaapsMessage, err := jaap.Encrypt(msg, ingrid.public)
	if err != nil {
		t.Errorf("Unable to encrypt Jaap's message for Ingrid; %s", err)
	}

	// Decrypt
	hm, _ := ingrid.Decrypt(henksMessage)
	jm, _ := ingrid.Decrypt(jaapsMessage)

	// Compare the messages of Henk and Jaap, and the original
	if !bytes.Equal(hm[:], jm[:]) && !bytes.Equal(hm[:], msg) {
		t.Error("Comparing Henk and Jaaps message; byte arrays are not the same")
	}
}

func TestEncryptionNeverTheSame(t *testing.T) {
	// Even when using the same public key, the encrypted messages are never the same
	henk, _ := NewRsaIdentity()
	jaap, _ := NewRsaIdentity()
	joop, _ := NewRsaIdentity()
	koos, _ := NewRsaIdentity()
	kees, _ := NewRsaIdentity()
	erik, _ := NewRsaIdentity()

	identities := []*RsaIdentity{henk, jaap, joop, koos, kees, erik}

	ingrid, _ := NewRsaIdentity()

	msg := []byte("Aan ons land geen polonaise.")
	var msgs [][]byte

	for _, id := range identities {
		// encrypt the message using Ingrid her public key
		e, _ := id.Encrypt(msg, ingrid.public)
		msgs = append(msgs, e)
	}

	s := []byte("start")
	for _, m := range msgs {
		if bytes.Equal(m[:], s[:]) {
			t.Error("Unable to decrypt Henk's message for Ingrid; byte arrays are not the same")
		}
	}

}

func TestEncryptDecrypt(t *testing.T) {
	henk, _ := NewRsaIdentity()
	ingrid, _ := NewRsaIdentity()

	// a message from Henk to Ingrid
	msg := []byte("Die uitkeringstrekkers pikken al onze banen in.")
	// Lets encrypt it, we want to sent it to Ingrid, thus, we need her public key.
	encryptedMessage, err := henk.Encrypt(msg, ingrid.public)

	if err != nil {
		t.Errorf("Unable to encrypt Henk's message for Ingrid; %s", err)
	}

	// Decrypt Message
	plainTextMessage, err := ingrid.Decrypt(encryptedMessage)

	if err != nil {
		t.Errorf("Unable to decrypt Henk's message for Ingrid; %s", err)
	}

	if !bytes.Equal(plainTextMessage[:], msg[:]) {
		t.Error("Unable to decrypt Henk's message for Ingrid; byte arrays are not the same")
	}
}

func TestEncryptDecryptMyself(t *testing.T) {
	// If anyone, even you, encrypts (id.e. “locks”) something with your public-key,
	// only you can decrypt it (id.e. “unlock” it) with your secret, private key.
	henk, _ := NewRsaIdentity()

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

func TestSignVerify(t *testing.T) {
	henk, _ := NewRsaIdentity()

	// A public message from Hans.
	// note that the message is a byte array, not just a string.
	msg := []byte("Wilders doet tenminste iets tegen de politiek.")
	// Henk signs the message with his private key. This will show the recipient
	// proof that this message is indeed from Henk
	sig, err := henk.Sign(msg)

	// now, if the message msg is public, anyone can read it.
	// the signature sig however, proves this message is from Henk.
	ingrid, _ := NewRsaIdentity()
	hans, _ := NewRsaIdentity()

	err = ingrid.Verify(msg, sig, henk.public)
	if err != nil {
		t.Errorf("Unable to verify Henk's signature; %s", err)
	}

	err = hans.Verify(msg, sig, henk.public)
	if err != nil {
		t.Errorf("Unable to verify Henk's signature; %s", err)
	}

	// Let's see if we can break the signature verification
	// (1) changing the message
	err = hans.Verify([]byte("Wilders is een opruier"), sig, henk.public)
	if err == nil {
		t.Error("Expected an error as we changed the message")
	}

	// (2) changing the signature
	err = hans.Verify(msg, []byte("I am not the signature"), henk.public)
	if err == nil {
		t.Error("Expected an error as we changed the signature")
	}

	// (3) changing the public key
	err = hans.Verify(msg, sig, ingrid.public)
	if err == nil {
		t.Error("Expected an error as we changed the public key")
	}
}
