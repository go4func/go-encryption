package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	ref1 = "thisisreference1"
	ref2 = "thisisreference2"
	key  = "this-is-32-byte-length-key!!!!!!"
)

func main() {
	test()
}

func test() {
	cipherText, err := Encrypt([]byte(fmt.Sprintf("%s%s", ref1, ref2)), []byte(key))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("cipher", cipherText)
	enc := Encode(cipherText)
	fmt.Println("encode", enc)

	dec, err := Decode(enc)
	if err != nil {
		panic(err)
	}
	fmt.Println("decode", dec)

	result, err := Decrypt(dec, []byte(key))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(result))
}

func Encode(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

func Decode(str string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(str)
}

// Encrypt encrypt plainText by secret key in GMC mode.
// The key should be 16 bytes (AES-128) or 32 (AES-256).
// Random nonce (default 12 bytes length) will be used to encrypt and prepend to the result
func Encrypt(plainText, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plainText, nil), nil
}

// Decrypt decrypt cipherText by secret key,
// nonce will be removed before decrypt.
func Decrypt(cipherText, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("ciphertext is invalid")
	}

	nonce, ciphertext := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
