package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const MEM_SIZE = 5 * 1024
const F = "0KXQsNC80LTQsNC80L7Qsgo="

func handleRSA(w http.ResponseWriter, r *http.Request) {

	err := r.ParseMultipartForm(MEM_SIZE)
	handleErr(err)

	// parse key
	fkey, _, err := r.FormFile("key")
	handleErr(err)

	privKey, err := ioutil.ReadAll(fkey)
	handleErr(err)

	// parse secret
	secret, _, err := r.FormFile("secret")
	handleErr(err)

	secretMsg, err := ioutil.ReadAll(secret)
	handleErr(err)

	// decrypt message
	block, _ := pem.Decode(privKey)
	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	handleErr(err)

	res, err := rsa.DecryptOAEP(sha1.New(), nil, pkey, secretMsg, nil)
	handleErr(err)

	fmt.Fprint(w, string(res))
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

	r.HandleFunc("/decrypt", handleRSA).Methods(http.MethodPost)
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		d, _ := base64.StdEncoding.DecodeString(F)
		fmt.Fprint(w, string(d))
	})
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello!")
	})

	// lookup port
	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "8080"
	}
	addr := fmt.Sprintf("0.0.0.0:%s", port)

	http.ListenAndServe(addr, handlers.CORS(origins, headers)(r))
}
