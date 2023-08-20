package goeds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func GenerateKey(bytesLen int) ([]byte, error) {
	// On genere la cle
	key := make([]byte, bytesLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("unable to generate the key")
	}

	// On renvoi la cle
	return key, nil
}

func gcmEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	// On genere le cipher bloc
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil, errors.New("unable to generate the cipher bloc")
	}

	// On genere le nonce (Never use more than 2^32 random nonces with a given key because of the risk of a repeat)
	nonce := make([]byte, GCM_NONCE_SIZE)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("unable to generate the nonce")
	}

	// On genere le bloc AES GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("unable to generate the aecgcm bloc from cipher bloc")
	}

	// On chiffre
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// On genere le resultat avec nonce suivi des data ciphered
	return append(nonce, ciphertext...), nil
}

func gcmDecrypt(key []byte, data []byte) ([]byte, error) {
	// On genere le cipher bloc
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("unable to generate the cipher bloc")
	}

	// On genere le bloc AES GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("unable to generate the aecgcm bloc from cipher bloc")
	}

	// On dechiffre
	plaintext, err := aesgcm.Open(nil, data[0:GCM_NONCE_SIZE], data[GCM_NONCE_SIZE:], nil)
	if err != nil {
		return nil, errors.New("unable to decrypt : " + err.Error())
	}

	// On renvoie les data
	return plaintext, nil
}
