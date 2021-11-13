package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"image"
	_ "image/png"
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// parse key
	fkey, _, err := r.FormFile("key")
	if fkey == nil {
		http.Error(w, "Empty file", http.StatusBadRequest)
		return
	}
	handleErr(err)

	privKey, err := ioutil.ReadAll(fkey)
	handleErr(err)

	// parse secret
	secret, _, err := r.FormFile("secret")
	if secret == nil {
		http.Error(w, "Empty file", http.StatusBadRequest)
		return
	}
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

func handleImg(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Access-Control-Allow-Origin", "*")

	_, fh, err := r.FormFile("image")
	handleErr(err)

	f, err := fh.Open()
	handleErr(err)

	img, _, _ := image.DecodeConfig(f)

	w.Header().Set("Content-Type", "application/json")
	res := fmt.Sprintf(`{"width":%d, "height":%d}`, img.Width, img.Height)
	fmt.Fprint(w, res)

	return
}

func handleErr(err error) {
	if err != nil {
		log.Println(err)
		return
	}
}

func main() {
	r := mux.NewRouter()

	origins := handlers.AllowedOrigins([]string{"*"})
	methods := handlers.AllowedMethods([]string{"*"})
	headers := handlers.AllowedHeaders([]string{"*"})

	r.HandleFunc("/decrypt", handleRSA).Methods(http.MethodPost)

	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")

		//d, _ := base64.StdEncoding.DecodeString(F)
		login := "lime"
		fmt.Fprint(w, login)
	})

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")

		fmt.Fprint(w, "Hello!")
	})

	r.HandleFunc("/size2json", handleImg).Methods(http.MethodPost)

	// lookup port
	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "8080"
	}
	addr := fmt.Sprintf("0.0.0.0:%s", port)

	http.ListenAndServe(addr, handlers.CORS(origins, methods, headers)(r))
}
