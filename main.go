package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const MEM_SIZE = 5 * 1024

func handleRSA(w http.ResponseWriter, r *http.Request) {

	err := r.ParseMultipartForm(MEM_SIZE)
	handleErr(err)

	// parse key
	fkey, _, err := r.FormFile("key")
	handleErr(err)

	privKey, err := io.ReadAll(fkey)
	handleErr(err)

	// parse secret
	secret, _, err := r.FormFile("secret")
	handleErr(err)

	secretMsg, err := io.ReadAll(secret)
	handleErr(err)

	// decrypt message
	block, _ := pem.Decode(privKey)
	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	handleErr(err)

	res, err := rsa.DecryptOAEP(sha1.New(), nil, pkey, secretMsg, nil)
	handleErr(err)

	io.WriteString(w, string(res))
}

func handleErr(err error) {
	if err != nil {
		log.Fatal(err)
		return
	}
}

func main() {
	r := mux.NewRouter()

	origins := handlers.AllowedOrigins([]string{"*"})
	headers := handlers.AllowedHeaders([]string{"*"})

	r.HandleFunc("/", handleRSA).Methods(http.MethodPost)

	http.ListenAndServe("0.0.0.0:8080", handlers.CORS(origins, headers)(r))
}
