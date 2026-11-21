package dynamic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMongoURIWithoutInsecureTLS(t *testing.T) {
	for in, want := range map[string]string{
		"mongodb://h/app?tls=true&tlsInsecure=true":                     "mongodb://h/app?tls=true",
		"mongodb://h/app?tlsInsecure=true&tls=true&appName=x":           "mongodb://h/app?tls=true&appName=x",
		"mongodb://h/app?tls=true;SSLINSECURE=true;appName=x":           "mongodb://h/app?tls=true&appName=x",
		"mongodb://h/app?tlsInsecure=true":                              "mongodb://h/app",
		"mongodb://h/app?tls=true":                                      "mongodb://h/app?tls=true",
		"mongodb://h/app":                                               "mongodb://h/app",
		"mongodb://h":                                                   "mongodb://h",
		"mongodb://u:p%3Fx@h/app?tls=true&tlsInsecure=true&authSource=": "mongodb://u:p%3Fx@h/app?tls=true&authSource=",
	} {
		got, _ := mongoURIWithoutInsecureTLS(in)
		assert.Equal(t, want, got, in)
	}
}
