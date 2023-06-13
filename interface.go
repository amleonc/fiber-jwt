package fiber_jwt

import (
	"errors"
	"log"
	"reflect"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

type SignatureAlgorithm = jwa.SignatureAlgorithm

type Extractor func(*fiber.Ctx) string

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
	// authenticator is the function to send http responses,
	// depending on the result of the token validation.
	authenticator fiber.Handler
	// userCtxKey is the key in the context which will hold the
	// user information. Default: "user".
	userCtxKey string
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
	verifier   jwt.ParseOption
}

const (
	ES256  SignatureAlgorithm = "ES256"  // ECDSA using P-256 and SHA-256
	ES256K SignatureAlgorithm = "ES256K" // ECDSA using secp256k1 and SHA-256
	ES384  SignatureAlgorithm = "ES384"  // ECDSA using P-384 and SHA-384
	ES512  SignatureAlgorithm = "ES512"  // ECDSA using P-521 and SHA-512
	EdDSA  SignatureAlgorithm = "EdDSA"  // EdDSA signature algorithms
	HS256  SignatureAlgorithm = "HS256"  // HMAC using SHA-256
	HS384  SignatureAlgorithm = "HS384"  // HMAC using SHA-384
	HS512  SignatureAlgorithm = "HS512"  // HMAC using SHA-512
	PS256  SignatureAlgorithm = "PS256"  // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384  SignatureAlgorithm = "PS384"  // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512  SignatureAlgorithm = "PS512"  // RSASSA-PSS using SHA512 and MGF1-SHA512
	RS256  SignatureAlgorithm = "RS256"  // RSASSA-PKCS-v1.5 using SHA-256
	RS384  SignatureAlgorithm = "RS384"  // RSASSA-PKCS-v1.5 using SHA-384
	RS512  SignatureAlgorithm = "RS512"  // RSASSA-PKCS-v1.5 using SHA-512
)

var defaultJWT = JWT{
	Filter: nil,
	SuccessHandler: func(ctx *fiber.Ctx) error {
		return ctx.Next()
	},
	ErrorHandler: func(ctx *fiber.Ctx, err error) error {
		if jwt.IsValidationError(err) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("Invalid or expired JWT")
		}
		return ctx.Status(fiber.StatusBadRequest).SendString("Missing or malformed JWT")
	},
	userCtxKey:  "user",
	alg:         "HS256",
	tokenLookup: "cookie:jwt",
	authScheme:  "Bearer",
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
type identWithSignKey struct{}
type identWithVerifyKey struct{}
type identWithKeySet struct{}
type identWithTokenLookup struct{}

func WithNextFunc(f func(*fiber.Ctx) bool) JWTOption {
	return &identConstraintStruct{option.New(identWithNextFunc{}, f)}
}

func WithAlgorithm(alg SignatureAlgorithm) JWTOption {
	return &identConstraintStruct{option.New(identWithAlgorithm{}, alg)}
}

func WithUserCtxKey(key string) JWTOption {
	return &identConstraintStruct{option.New(identWithUserCtxKey{}, key)}
}

func WithSignKey(key any) JWTOption {
	k, err := jwk.FromRaw(key)
	if err != nil {
		t := reflect.TypeOf(k)
		log.Fatalf("invalid signing key of type `%s`, expected RSA, ECDSA or byte array\n", t)
	}
	return &identConstraintStruct{option.New(identWithSignKey{}, k)}
}

func WithVerifyKey(key any) JWTOption {
	k, err := jwk.FromRaw(key)
	if err != nil {
		t := reflect.TypeOf(k)
		log.Fatalf("invalid verifying key of type `%s`, expected RSA, ECDSA or byte array\n", t)
	}
	return &identConstraintStruct{option.New(identWithVerifyKey{}, k)}
}

// func WithKeySet(set jwk.Set) JWTOption {
// 	return &identConstraintStruct{option.New(identWithKeySet{}, set)}
// }

func WithTokenLookup(schema string) JWTOption {
	return &identConstraintStruct{option.New(identWithTokenLookup{}, schema)}
}

func New(options ...JWTOption) JWT {
	j := defaultJWT
	for _, o := range options {
		switch o.Ident() {
		case identWithNextFunc{}:
			j.Filter = o.Value().(func(*fiber.Ctx) bool)
		case identWithAlgorithm{}:
			j.alg = o.Value().(SignatureAlgorithm)
		case identWithUserCtxKey{}:
			j.userCtxKey = o.Value().(string)
		case identWithSignKey{}:
			j.signKey = o.Value().(jwk.Key)
		case identWithVerifyKey{}:
			j.verifyKey = o.Value().(jwk.Key)
		case identWithKeySet{}:
			j.keySet = o.Value().(jwk.Set)
		}
	}
	lookups := strings.Split(j.tokenLookup, ",")
	for _, lookup := range lookups {
		parts := strings.Split(lookup, ":")
		switch parts[0] {
		case "cookie":
			j.extractors = append(j.extractors, fromCookie(parts[1]))
		case "header":
			j.extractors = append(j.extractors, fromHeader(parts[1], j.authScheme))
		}
	}
	if len(j.extractors) == 0 {
		panic("empty extractors, please check your token lookup schema")
	}
	return j
}

var (
	ErrMissingJWT     = errors.New("missing jwt")
	ErrInvalidPayload = errors.New("cannot map claims")
)

func (j *JWT) Serve() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if j.Filter != nil && j.Filter(ctx) {
			return ctx.Next()
		}
		t, err := verifyRequest(j, ctx)
		if err != nil {
			return j.ErrorHandler(ctx, err)
		}
		claims, err := t.AsMap(ctx.UserContext())
		if err != nil {
			return ErrInvalidPayload
		}
		for k, v := range claims {
			ctx.Locals(k, v)
		}
		return j.SuccessHandler(ctx)
	}
}

func verifyRequest(j *JWT, ctx *fiber.Ctx) (jwt.Token, error) {
	var ts string
	for _, fn := range j.extractors {
		ts = fn(ctx)
		if ts != "" {
			break
		}
	}
	// NOTE: is this validation really necessary?
	if ts == "" {
		return nil, ErrMissingJWT
	}
	return verifyToken(j, ts)
}

func verifyToken(j *JWT, tokenString string) (jwt.Token, error) {
	token := jwt.New()
	var options []jwt.ParseOption
	options = append(options, jwt.WithToken(token), j.verifier, jwt.WithValidate(false))
	_, err := jwt.ParseString(tokenString, options...)
	if err != nil {
		return nil, err
	}
	return token, nil
}
