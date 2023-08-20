package goeds

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	gofs "github.com/craimbault/go-fs"
)

const (
	KEY_BYTES_LEN  = 32
	GCM_NONCE_SIZE = 12
)

var (
	ErrKeyExists = errors.New("this key already exists")
)

func NewFromMasterKeyFile(masterKeyFilePath string, gfs *gofs.GoFS) (*GoEDS, error) {
	masterPassPhrase, err := os.ReadFile(masterKeyFilePath)
	if err != nil {
		return nil, errors.New("unable to get master key : " + err.Error())
	}

	return NewWithConfig(
		GoEDSConfig{
			MasterPassPhrase: masterPassPhrase,
		},
		gfs,
	)
}

func New(masterPassPhrase []byte, gfs *gofs.GoFS) (*GoEDS, error) {
	config := GoEDSConfig{
		MasterPassPhrase: masterPassPhrase,
	}

	return NewWithConfig(config, gfs)
}

func NewWithConfig(config GoEDSConfig, gfs *gofs.GoFS) (*GoEDS, error) {
	// On initialise GoEDS
	goEds := GoEDS{
		config: config,
		gofs:   gfs,
	}

	// Si la cle ne fait pas la bonne longueur
	if len(config.MasterPassPhrase) != KEY_BYTES_LEN {
		return nil, errors.New("master passphrase must be of " + fmt.Sprint(KEY_BYTES_LEN) + " bytes length")
	}

	return &goEds, nil
}

func (g *GoEDS) masterEncrypt(plaintext []byte) ([]byte, error) {
	return gcmEncrypt(
		[]byte(g.config.MasterPassPhrase),
		plaintext,
	)
}

func (g *GoEDS) masterDecrypt(ciphertext []byte) ([]byte, error) {
	return gcmDecrypt(
		[]byte(g.config.MasterPassPhrase),
		ciphertext,
	)
}

func (g *GoEDS) getDecryptedKey(keyName string) ([]byte, error) {
	// On recupere la cle chiffree
	cipheredKey, err := g.gofs.Read(keyName)
	if err != nil {
		return nil, errors.New("unable to get key : " + err.Error())
	}

	// On la déchiffre
	return g.masterDecrypt(cipheredKey)
}

func (g *GoEDS) KeyExists(keyName string) bool {
	// On regarde si la cle existe
	_, err := g.gofs.Stat(keyName)
	return err == nil
}

func (g *GoEDS) GenerateNewKey(keyName string) error {
	// On bloque le temps de la generation
	g.mu.Lock()
	defer g.mu.Unlock()

	// Si la cle existe
	_, err := g.gofs.Stat(keyName)
	if err == nil {
		return ErrKeyExists
	}

	// On genere une nouvelle cle
	newKey, err := GenerateKey(KEY_BYTES_LEN)
	if err != nil {
		return errors.New("unable to generate a new key : " + err.Error())
	}

	// On la chiffre
	newEncryptedKey, err := g.masterEncrypt(newKey)
	if err != nil {
		return errors.New("unable to master encrypt the new key : " + err.Error())
	}

	// On l'enregistre sur le stockage
	err = g.gofs.Write(keyName, newEncryptedKey)
	if err != nil {
		return errors.New("unable to save the key on storage : " + err.Error())
	}

	// On indique que tout est Ok
	return nil
}

// encrypt the provided plaintext (data in bytes) and return a bytes result
func (g *GoEDS) Encrypt(keyName string, plaintext []byte) ([]byte, error) {
	// On recupere la cle de chiffrement
	key, err := g.getDecryptedKey(keyName)
	if err != nil {
		return nil, errors.New("Unable to retreive the cypher key : " + err.Error())
	}

	// On chiffre en GCM
	return gcmEncrypt(key, plaintext)
}

// encrypt the provided data (from string) and return a bytes result
func (g *GoEDS) StringEncrypt(keyName string, stringPlaintext string) ([]byte, error) {
	// On passe le plaintext en bytes et on utilise la methode existante
	return g.Encrypt(
		keyName,
		([]byte)(stringPlaintext),
	)
}

// encrypt the provided data and return a Base64 string result
func (g *GoEDS) EncryptToBase64(keyName string, plaintext []byte) (string, error) {
	// On chiffre
	cipheredtext, err := g.Encrypt(keyName, plaintext)
	if err != nil {
		return "", errors.New("encryption error : " + err.Error())
	}

	// On renvoi en base64
	return base64.StdEncoding.EncodeToString(cipheredtext), nil
}

// encrypt the provided data (from string) and return a Base64 string result
func (g *GoEDS) StringEncryptToBase64(keyName string, stringPlaintext string) (string, error) {
	// On passe le plaintext en bytes et on utilise la methode existante
	return g.EncryptToBase64(
		keyName,
		([]byte)(stringPlaintext),
	)
}

// decrypt the provided data ("nonce.cipheredtext" from bytes) and return a bytes result
func (g *GoEDS) Decrypt(keyName string, data []byte) ([]byte, error) {
	// On recupere la cle de chiffrement
	key, err := g.getDecryptedKey(keyName)
	if err != nil {
		return nil, errors.New("Unable to retreive the cypher key : " + err.Error())
	}

	// On appel la methode de dechiffrement
	return gcmDecrypt(key, data)
}

// decrypt the provided data ("nonce.cipheredtext" from bytes) and return a string result
func (g *GoEDS) DecryptToString(keyName string, data []byte) (string, error) {
	// On dechiffre
	plaintext, err := g.Decrypt(keyName, data)
	if err != nil {
		return "", errors.New("decryption error : " + err.Error())
	}

	// On renvoie en string
	return (string)(plaintext), nil
}

// decrypt the provided data ("nonce.cipheredtext" from Base64string) and return a bytes result
func (g *GoEDS) Base64Decrypt(keyName string, base64Data string) ([]byte, error) {
	// On decode le base64
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, errors.New("base64 decryption error : " + err.Error())
	}

	// On dechiffre
	return g.Decrypt(keyName, data)
}

// decrypt the provided data ("nonce.cipheredtext" from Base64string) and return a string result
func (g *GoEDS) Base64DecryptToString(keyName string, base64Data string) (string, error) {
	// On dechiffre
	plaintext, err := g.Base64Decrypt(keyName, base64Data)
	if err != nil {
		return "", errors.New("decryption error : " + err.Error())
	}

	// On renvoie en string
	return (string)(plaintext), nil
}
