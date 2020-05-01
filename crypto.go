package goencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
)

//MakeEncryptionKey : Generates a new key that can be used in encryption
func MakeEncryptionKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return fmt.Sprintf("%x", key)
}

//EncryptText : Encryots the plaintext provided
func EncryptText(key string, plaintext string) (string, error) {
	var ciphertext []byte
	hexKey, err := hex.DecodeString(key)
	if err != nil {
		log.Println(err)
		return string(ciphertext), err
	}
	block, err := aes.NewCipher(hexKey)
	if err != nil {
		log.Println(err)
		return string(ciphertext), err
	}
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return string(ciphertext), err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
	return fmt.Sprintf("%x", ciphertext), nil
}

//DecryptText : Decrypts the plaintext provided
func DecryptText(key string, ciphertext string) (string, error) {
	var plaintext string
	var err error
	hexKey, err := hex.DecodeString(key)
	if err != nil {
		return plaintext, err
	}
	ciphertextHex, err := hex.DecodeString(ciphertext)
	if err != nil {
		return plaintext, err
	}
	block, err := aes.NewCipher(hexKey)
	if err != nil {
		log.Println(err)
		return plaintext, err
	}
	if len(ciphertextHex) < aes.BlockSize {
		return plaintext, errors.New("ciphertext too short")
	}
	iv := ciphertextHex[:aes.BlockSize]
	ciphertextHex = ciphertextHex[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextHex, ciphertextHex)
	plaintext = string(ciphertextHex)
	return plaintext, nil
}
