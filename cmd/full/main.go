package main

import (
	"log"
	"os"

	goeds "github.com/craimbault/go-eds"
	gofs "github.com/craimbault/go-fs"
	gofsLocal "github.com/craimbault/go-fs/pkg/backend/gofsbcklocal"
)

func main() {
	log.Println("FULL START")

	// !! DO NOT USE IN PRODUCTION !!! Use goeds.GenerateKey(goeds.KEY_BYTES_LEN) instead
	demoKey := []byte("12345678901234567890123456789012")

	// On definit le chemin de base pour GoFS
	basePath, _ := os.Getwd()
	basePath += string(os.PathSeparator) + "data"
	mkdirErr := os.MkdirAll(basePath, 0777)
	if mkdirErr != nil {
		log.Fatal("Unable to create base path :", basePath)
	}

	// On genere la config et le backend GoFS
	gfsConfig := gofsLocal.LocalConfig{
		BasePath: basePath,
		Debug:    false,
	}
	gfs, gfsErr := gofs.New(
		gofs.BACKEND_TYPE_LOCAL,
		gfsConfig,
	)
	if gfsErr != nil {
		log.Fatal("Unable to initialize GoFS Backend : " + gfsErr.Error())
	}

	// On genere GoEDS
	geds, gedsErr := goeds.New(
		demoKey,
		&gfs,
	)
	if gedsErr != nil {
		log.Fatal("Unable to initialize GoEDS Backend : " + gfsErr.Error())
	}

	// On  prend des infos de test
	keyName := "my-test-key"
	plaintext := "#text to encrypt#"

	// Si la cle existe pas
	if !geds.KeyExists(keyName) {
		// On genere la cle
		genErr := geds.GenerateNewKey(keyName)
		if genErr != nil {
			log.Fatal("Unable to generate the Key : " + genErr.Error())
		}
	}

	// On chiffre le contenu
	encryptedBase64, encryptedErr := geds.StringEncryptToBase64(keyName, plaintext)
	if encryptedErr != nil {
		log.Fatal("Unable to encrypt data : " + encryptedErr.Error())
	}

	// On dechiffre le contenu
	decryptedString, decryptedErr := geds.Base64DecryptToString(keyName, encryptedBase64)
	if decryptedErr != nil {
		log.Fatal("Unable to decrypt data : " + decryptedErr.Error())
	}

	// On l'affiche
	log.Printf("\n\tPlaintext \t\t: %s\n\tEncrypted to Base64 \t: %s\n\tDecrypted \t\t: %s\n", plaintext, encryptedBase64, decryptedString)

	log.Println("FULL END")
}
