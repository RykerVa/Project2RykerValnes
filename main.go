package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"strconv"
	"time"
	"errors"
	"math/big"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"database/sql"
)

const (
	dbPath         = "totally_not_my_privateKeys.db"
	authorizedKID  = "AuthorizedGoodKeyID"
	serverPort     = ":8080"
	expirationTime = 1 * time.Hour
)

func main() {
	db := initDB(dbPath)
	defer db.Close()

	initializeKeyStore(db)

	r := mux.NewRouter()
	r.HandleFunc("/.well-known/jwks.json", jwksHandler(db)).Methods("GET")
	r.HandleFunc("/auth", authHandler(db)).Methods("POST")

	log.Println("Starting server on", serverPort)
	if err := http.ListenAndServe(serverPort, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func initDB(dbPath string) *sql.DB {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS keys (
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`

	if _, err = db.Exec(createTableSQL); err != nil {
		log.Fatalf("Error creating keys table: %v", err)
	}

	return db
}

func initializeKeyStore(db *sql.DB) {
	generateAndStoreKey(db, time.Now().Add(expirationTime).Unix())  // Valid key
	generateAndStoreKey(db, time.Now().Add(-expirationTime).Unix()) // Expired key
}

func generateAndStoreKey(db *sql.DB, exp int64) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", privateKeyPEM, exp)
	if err != nil {
		log.Fatalf("Error inserting key into database: %v", err)
	}
}

func jwksHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys := getKeysFromDB(db)
		resp := JWKS{Keys: keys}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func getKeysFromDB(db *sql.DB) []JWK {
	var keys []JWK
	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		log.Println("Database error:", err)
		return keys
	}
	defer rows.Close()

	for rows.Next() {
		var kid int
		var keyPEM []byte
		if err := rows.Scan(&kid, &keyPEM); err != nil {
			log.Println("Failed to fetch keys:", err)
			continue
		}
		block, _ := pem.Decode(keyPEM)
		if block == nil {
			log.Println("Failed to parse PEM block containing the key")
			continue
		}

		pubKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Println("Failed to parse private key:", err)
			continue
		}
		jwk := generateJWK(pubKey.Public().(*rsa.PublicKey), strconv.Itoa(kid))
		keys = append(keys, jwk)
	}
	return keys
}

func generateJWK(pubKey *rsa.PublicKey, kid string) JWK {
	return JWK{
		KID:       kid,
		Algorithm: "RS256",
		KeyType:   "RSA",
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}
}

func authHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username, _, ok := r.BasicAuth()
		if !ok {
			var creds struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
				http.Error(w, "Invalid authentication method!", http.StatusBadRequest)
				return
			}
			username = creds.Username
		}

		expired, _ := strconv.ParseBool(r.URL.Query().Get("expired"))
		signingKey, kid, err := fetchSigningKey(db, expired)
		if err != nil {
			http.Error(w, "Failed to fetch key", http.StatusInternalServerError)
			return
		}

		claims := jwt.MapClaims{
			"iss": "jwks-server",
			"sub": username,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid

		tokenString, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "Failed to sign token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

func fetchSigningKey(db *sql.DB, expired bool) (*rsa.PrivateKey, string, error) {
	var keyPEM []byte
	var kid int
	var err error

	if expired {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp <= ?", time.Now().Unix()).Scan(&kid, &keyPEM)
	} else {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&kid, &keyPEM)
	}

	if err != nil {
		return nil, "", err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, "", errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}

	return privateKey, strconv.Itoa(kid), nil
}

type JWK struct {
	KID       string `json:"kid"`
	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

