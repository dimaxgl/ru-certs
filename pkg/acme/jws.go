package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key for RSA or EC
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWSHeader represents JWS protected header
type JWSHeader struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
	KID   string `json:"kid,omitempty"`
	JWK   *JWK   `json:"jwk,omitempty"`
}

// JWSRequestBody is the RFC 8555 body
type JWSRequestBody struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// KeyAuthorization computes token.thumbprint for ACME challenge
func KeyAuthorization(token string, signer crypto.Signer) (string, error) {
	thumb, err := JWKThumbprint(signer.Public())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, thumb), nil
}

// KeyAuthorizationSHA256 returns base64url(SHA256(KeyAuthorization)) for DNS-01 TXT record
func KeyAuthorizationSHA256(token string, signer crypto.Signer) (string, error) {
	ka, err := KeyAuthorization(token, signer)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(ka))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// JWKThumbprint computes SHA-256 JWK Thumbprint (RFC 7638)
func JWKThumbprint(pub crypto.PublicKey) (string, error) {
	jwk, err := PublicKeyToJWK(pub)
	if err != nil {
		return "", err
	}

	var canonicalJSON []byte
	switch jwk.Kty {
	case "RSA":
		canonicalJSON = []byte(fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk.E, jwk.N))
	case "EC":
		canonicalJSON = []byte(fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, jwk.Crv, jwk.X, jwk.Y))
	default:
		return "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	hash := sha256.Sum256(canonicalJSON)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// PublicKeyToJWK converts crypto.PublicKey to JWK struct
func PublicKeyToJWK(pub crypto.PublicKey) (*JWK, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return &JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		crv := k.Curve.Params().Name
		if crv == "P-256" {
			crv = "P-256"
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()
		xPad := make([]byte, byteLen-len(xBytes))
		yPad := make([]byte, byteLen-len(yBytes))
		return &JWK{
			Kty: "EC",
			Crv: crv,
			X:   base64.RawURLEncoding.EncodeToString(append(xPad, xBytes...)),
			Y:   base64.RawURLEncoding.EncodeToString(append(yPad, yBytes...)),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// SignJWS creates signed RFC 8555 JWS request
func SignJWS(signer crypto.Signer, kid string, url string, nonce string, payload []byte) ([]byte, error) {
	hdr := JWSHeader{
		Nonce: nonce,
		URL:   url,
	}

	var alg string
	switch signer.(type) {
	case *rsa.PrivateKey:
		alg = "RS256"
	case *ecdsa.PrivateKey:
		alg = "ES256"
	default:
		return nil, fmt.Errorf("unsupported signer type")
	}
	hdr.Alg = alg

	if kid != "" {
		hdr.KID = kid
	} else {
		jwk, err := PublicKeyToJWK(signer.Public())
		if err != nil {
			return nil, err
		}
		hdr.JWK = jwk
	}

	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}

	protectedB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	var payloadB64 string
	if payload != nil {
		payloadB64 = base64.RawURLEncoding.EncodeToString(payload)
	}

	signInput := fmt.Sprintf("%s.%s", protectedB64, payloadB64)
	h := sha256.Sum256([]byte(signInput))

	var sig []byte
	switch s := signer.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, s, crypto.SHA256, h[:])
		if err != nil {
			return nil, fmt.Errorf("RSA sign failed: %w", err)
		}
	case *ecdsa.PrivateKey:
		r, sVal, err := ecdsa.Sign(rand.Reader, s, h[:])
		if err != nil {
			return nil, fmt.Errorf("ECDSA sign failed: %w", err)
		}
		byteLen := (s.Curve.Params().BitSize + 7) / 8
		rBytes := r.Bytes()
		sBytes := sVal.Bytes()
		sig = make([]byte, byteLen*2)
		copy(sig[byteLen-len(rBytes):byteLen], rBytes)
		copy(sig[byteLen*2-len(sBytes):], sBytes)
	}

	reqBody := JWSRequestBody{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}

	return json.Marshal(reqBody)
}
