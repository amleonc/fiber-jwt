package fiber_jwt

import (
	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

type SignatureAlgorithm = jwa.SignatureAlgorithm

type Extractor = func(*fiber.Ctx) string

type JWT struct {
	// Filter defines an optional function to skip the middleware
	// if a certain criteria is met. Default: nil.
	Filter func(c *fiber.Ctx) bool
	// SuccessHandler is called when the jwt verification process
	// succeeds, so it will call the next handler in the chain.
	SuccessHandler fiber.Handler
	// ErrorHandler is called when an error occurred during
	// the token verification.
	ErrorHandler fiber.ErrorHandler
	// userCtxKey is the key in the context which will hold the
	// user information. Default: "user".
	userCtxKey string
	// userInfo is a map holding info extracted from the token
	// regarding user information.
	userInfo map[string]any
	// alg the algorithm of the key model. Default: HS256.
	alg SignatureAlgorithm
	// signKey the object used to sign tokens.
	signKey jwk.Key
	// verifyKey the object used to verify tokens.
	verifyKey jwk.Key
	// keySet is used to sign and verify tokens according to
	// the key type (e.g. RSA). It is used if and only if both
	// signKey and verifyKey are nil.
	keySet jwk.Set
	// tokenLookup defines the places where the middleware
	// should look for tokens in the request, and the name of
	// the object representing the token itself.
	// Default: "cookie:jwt"
	tokenLookup string
	// authScheme is the scheme of the authorization header.
	// default: Bearer.
	authScheme string
	// extractors the functions used to extract tokens from the http request.
	extractors []Extractor
	verifier   jwk.Key
}

var defaultJWT = &JWT{
	Filter:     nil,
	userCtxKey: "user",
	userInfo:   nil,
	alg:        "HS256",
	extractors: []Extractor{FromCookie},
}

type JWTOption interface {
	Option
	jwtConstraintMethod()
}

type identConstraintStruct struct {
	Option
}

func (i *identConstraintStruct) jwtConstraintMethod() {}

type identWithNextFunc struct{}
type identWithAlgorithm struct{}
type identWithUserCtxKey struct{}
type identWithUserInfo struct{}
type identWithSignKey struct{}
type identWithVerifyKey struct{}
type identWithKeySet struct{}
type identWithExtractors struct{}

func WithNextFunc(f func(*fiber.Ctx) bool) JWTOption {
	return &identConstraintStruct{option.New(identWithNextFunc{}, f)}
}

func WithAlgorithm(alg SignatureAlgorithm) JWTOption {
	return &identConstraintStruct{option.New(identWithAlgorithm{}, alg)}
}

func WithUserCtxKey(key string) JWTOption {
	return &identConstraintStruct{option.New(identWithUserCtxKey{}, key)}
}

func WithUserInfo(info map[string]any) JWTOption {
	return &identConstraintStruct{option.New(identWithUserInfo{}, info)}
}

func WithSignKey(key any) JWTOption {
	// FIXME: parse the key using the jwk package
	return &identConstraintStruct{option.New(identWithSignKey{}, key)}
}

func WithVerifyKey(key any) JWTOption {
	// FIXME: parse the key using the jwk package
	return &identConstraintStruct{option.New(identWithVerifyKey{}, key)}
}

func WithExtractors(fn ...Extractor) JWTOption {
	return &identConstraintStruct{option.New(identWithExtractors{}, fn)}
}

func WithKeySet(set jwk.Set) JWTOption {
	return &identConstraintStruct{option.New(identWithKeySet{}, set)}
}

func New(options ...JWTOption) JWT {
	jwt := JWT{}
	for _, option := range options {
		switch option.Ident() {
		case identWithNextFunc{}:
			jwt.Filter = option.Value().(func(*fiber.Ctx) bool)
		case identWithAlgorithm{}:
			jwt.alg = option.Value().(SignatureAlgorithm)
		case identWithUserCtxKey{}:
			jwt.userCtxKey = option.Value().(string)
		case identWithUserInfo{}:
			jwt.userInfo = option.Value().(map[string]any)
		case identWithSignKey{}:
			jwt.signKey = option.Value().(jwk.Key)
		case identWithVerifyKey{}:
			jwt.verifyKey = option.Value().(jwk.Key)
		case identWithKeySet{}:
			jwt.keySet = option.Value().(jwk.Set)
		case identWithExtractors{}:
			jwt.extractors = option.Value().([]Extractor)
		}
	}
	return jwt
}
