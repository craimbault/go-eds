package goeds

import (
	"sync"

	gofs "github.com/craimbault/go-fs"
)

type GoEDSConfig struct {
	MasterPassPhrase []byte
}

type GoEDS struct {
	config GoEDSConfig
	gofs   *gofs.GoFS
	mu     sync.Mutex
}
