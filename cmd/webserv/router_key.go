package main

import (
	"net/http"

	goeds "github.com/craimbault/go-eds"
	"github.com/gin-gonic/gin"
)

func rk_create(c *gin.Context) {
	responseConde := 201

	err := geds.GenerateNewKey(c.Param(GIN_PATH_KEYNAME))
	if err != nil {
		switch err {
		case goeds.ErrKeyExists:
			responseConde = http.StatusConflict
		default:
			responseConde = http.StatusInternalServerError
		}
	}

	c.String(responseConde, "")
}

func rk_exists(c *gin.Context) {
	responseConde := 200
	if !geds.KeyExists(c.Param(GIN_PATH_KEYNAME)) {
		responseConde = 404
	}
	c.String(responseConde, "")
}

func rk_encrypt(c *gin.Context) {
	keyName := c.Param(GIN_PATH_KEYNAME)
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error_message": "Unable to get content from request",
			"error_details": err.Error(),
		})
		return
	}

	var (
		binData    []byte = nil
		stringData string = ""
		gedsErr    error
	)

	switch c.GetHeader("Content-Type") {
	case CONTENT_TYPE__OCTET_STREAM:
		switch c.GetHeader("Accept") {
		case CONTENT_TYPE__OCTET_STREAM:
			binData, gedsErr = geds.Encrypt(keyName, body)
		default:
			stringData, gedsErr = geds.EncryptToBase64(keyName, body)
		}
	default:
		switch c.GetHeader("Accept") {
		case CONTENT_TYPE__OCTET_STREAM:
			binData, gedsErr = geds.StringEncrypt(keyName, string(body))
		default:
			stringData, gedsErr = geds.StringEncryptToBase64(keyName, string(body))
		}
	}

	if gedsErr != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error_message": "Unable to encrypt data",
				"error_details": gedsErr.Error(),
			},
		)
		return
	}

	if len(stringData) > 0 {
		c.String(http.StatusOK, stringData)
	} else {
		c.Data(http.StatusOK, CONTENT_TYPE__OCTET_STREAM, binData)
	}
}

func rk_decrypt(c *gin.Context) {

	keyName := c.Param(GIN_PATH_KEYNAME)
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error_message": "Unable to get content from request",
			"error_details": err.Error(),
		})
		return
	}

	var (
		binData    []byte = nil
		stringData string = ""
		gedsErr    error
	)

	switch c.GetHeader("Content-Type") {
	case CONTENT_TYPE__OCTET_STREAM:
		switch c.GetHeader("Accept") {
		case CONTENT_TYPE__OCTET_STREAM:
			binData, gedsErr = geds.Decrypt(keyName, body)
		default:
			stringData, gedsErr = geds.DecryptToString(keyName, body)
		}
	default:
		switch c.GetHeader("Accept") {
		case CONTENT_TYPE__OCTET_STREAM:
			binData, gedsErr = geds.Base64Decrypt(keyName, string(body))
		default:
			stringData, gedsErr = geds.Base64DecryptToString(keyName, string(body))
		}
	}

	if gedsErr != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error_message": "Unable to decrypt data",
				"error_details": gedsErr.Error(),
			},
		)
		return
	}

	if len(stringData) > 0 {
		c.String(http.StatusOK, stringData)
	} else {
		c.Data(http.StatusOK, CONTENT_TYPE__OCTET_STREAM, binData)
	}
}
