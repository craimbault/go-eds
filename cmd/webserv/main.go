package main

import (
	"flag"
	"log"
	"net/http"

	goeds "github.com/craimbault/go-eds"
	gofs "github.com/craimbault/go-fs"
	"github.com/craimbault/go-fs/pkg/backend/gofsbcks3"
	"github.com/gin-gonic/gin"
)

const (
	GIN_PATH_KEYNAME        = "keyname"
	GIN_PATH_KEYNAME_MINLEN = 5

	CONTENT_TYPE__OCTET_STREAM = "application/octet-stream"
	CONTENT_TYPE__BASE64       = "application/base64"
)

var (
	LISTEN     string
	API_PREFIX string
	KEY_FILE   string
	KEY_STRING string

	S3_ENDPOINT    string
	S3_REGION      string
	S3_ACCESS_KEY  string
	S3_SECRET_KEY  string
	S3_USESSL      bool
	S3_BUCKET_NAME string
	S3_PATH_PREFIX string

	geds *goeds.GoEDS
)

func init() {
	// GoEDS
	flag.StringVar(&LISTEN, "listen", ":8042", "webserver listen host and port")
	flag.StringVar(&API_PREFIX, "api-prefix", "", "prefix to use on all ressources")
	flag.StringVar(&KEY_FILE, "key-file", "", "master key from file path")
	flag.StringVar(&KEY_STRING, "key-string", "", "master key from string flag")

	// S3 GoFS
	flag.StringVar(&S3_ENDPOINT, "s3_endpoint", "localhost:9000", "S3 Endpoint")
	flag.StringVar(&S3_REGION, "s3_region", "us-east-1", "S3 Region")
	flag.StringVar(&S3_ACCESS_KEY, "s3_access_key", "minioaccesskey", "S3 Access Key")
	flag.StringVar(&S3_SECRET_KEY, "s3_secret_key", "miniosecretkey", "S3 Secret Key")
	flag.BoolVar(&S3_USESSL, "s3_use_ssl", false, "S3 Use SSL")
	flag.StringVar(&S3_BUCKET_NAME, "s3_bucket_name", "goeds-s3-webserv", "S3 Bucket Name")
	flag.StringVar(&S3_PATH_PREFIX, "s3_path_prefix", "", "S3 Path Prefix")
}

func main() {
	log.Println("WEBSRV START")
	flag.Parse()

	// On verifie que l'on a pas les 2 methodes pour init GoEDS
	if len(KEY_FILE) > 0 && len(KEY_STRING) > 0 {
		log.Fatal("params key-file & key-string provided at the same time, please use only one at time")
	} else if len(KEY_FILE) < goeds.KEY_BYTES_LEN && len(KEY_STRING) < goeds.KEY_BYTES_LEN {
		log.Fatal("missing params key-file or key-string, please provide at least one")
	}

	// On init GFS
	gfs, gfsInitErr := gofs.New(
		gofs.BACKEND_TYPE_S3,
		gofsbcks3.S3Config{
			Endpoint:        S3_ENDPOINT,
			Region:          S3_REGION,
			AccessKeyID:     S3_ACCESS_KEY,
			SecretAccessKey: S3_SECRET_KEY,
			UseSSL:          S3_USESSL,
			BucketName:      S3_BUCKET_NAME,
			PathPrefix:      S3_PATH_PREFIX,
		},
	)
	if gfsInitErr != nil {
		log.Fatal("Unable to init GoFS : " + gfsInitErr.Error())
	}

	// On init GoEDS
	var gedsInitErr error
	if len(KEY_FILE) > 0 {
		geds, gedsInitErr = goeds.NewFromMasterKeyFile(KEY_FILE, &gfs)
	} else {
		geds, gedsInitErr = goeds.New([]byte(KEY_STRING), &gfs)
	}
	if gedsInitErr != nil {
		log.Fatal("Unable to init GoEds : " + gedsInitErr.Error())
	}

	// On init Gin
	router := gin.Default()
	gedsRouter := router.Group(API_PREFIX + "/geds/:" + GIN_PATH_KEYNAME)
	gedsRouter.Use(gedsKeyNameMinLength())
	gedsRouter.POST("", rk_create)
	gedsRouter.HEAD("", rk_exists)
	gedsRouter.POST("/encrypt", rk_encrypt)
	gedsRouter.POST("/decrypt", rk_decrypt)

	// On demarre le serveur web
	websrv := &http.Server{
		Addr:    LISTEN,
		Handler: router,
	}
	err := websrv.ListenAndServe()
	if err != nil {
		log.Fatal("Gin WebServer Error : " + err.Error())
	}

	log.Println("WEBSRV END")
}

func gedsKeyNameMinLength() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Param(GIN_PATH_KEYNAME)) < GIN_PATH_KEYNAME_MINLEN {
			c.JSON(http.StatusPreconditionFailed, gin.H{})
			return
		}
	}
}
