// Description: Code borrowed and modified from the following sources:
//   https://gist.github.com/chadlung/c617e045750b73f6fe7f2f70d99fb321
//   https://github.com/kataras/iris/blob/master/_examples/experimental-handlers/jwt/main.go
//
// Author: John Deng


package main

// $ go get -u github.com/john-deng/jwt-demo

import (
	"github.com/kataras/iris"

	"github.com/dgrijalva/jwt-go"
	jwtmiddleware "github.com/iris-contrib/middleware/jwt"
	"strings"
	"time"
	"crypto/rsa"
	"github.com/hidevopsio/hi/boot/pkg/log"
	"io/ioutil"
)

const (
	// For simplicity these files are in the same folder as the app binary.
	// You shouldn't do this in production.
	privateKeyPath = "config/app.rsa"
	pubKeyPath     = "config/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Data string `json:"data"`
}

type Token struct {
	Token string `json:"token"`
}

func init()  {
	log.SetLevel(log.DebugLevel)
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func initKeys() {
	signBytes, err := ioutil.ReadFile(privateKeyPath)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)
}

func loginHandler(ctx iris.Context) {

	var user UserCredentials
	err := ctx.ReadJSON(&user)

	if err != nil {
		ctx.Text("Error in request")
		return
	}

	if strings.ToLower(user.Username) != "johndeng" {
		if user.Password != "p@ssword" {
			ctx.Text("Error logging in")
			return
		}
	}

	token := jwt.New(jwt.SigningMethodRS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(1)).Unix()
	claims["iat"] = time.Now().Unix()
	token.Claims = claims

	tokenString, err := token.SignedString(signKey)

	if err != nil {
		ctx.Text("Error on authorization")
		fatal(err)
	}

	response := &Token{tokenString}

	ctx.JSON(response)

}

func pingHandler(ctx iris.Context) {
	user := ctx.Values().Get("jwt").(*jwt.Token)

	ctx.Writef("This is an authenticated request\n")
	ctx.Writef("Claim content:\n")

	ctx.Writef("%s", user.Signature)
}

func main() {

	initKeys()

	app := iris.New()

	jwtHandler := jwtmiddleware.New(jwtmiddleware.Config{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			log.Debug(token)
			return verifyKey, nil
		},
		// When set, the middleware verifies that tokens are signed with the specific signing algorithm
		// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
		// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
		SigningMethod: jwt.SigningMethodRS256,
	})

	app.Post("/login", loginHandler)

	app.Use(jwtHandler.Serve)
	app.Get("/ping", pingHandler)
	app.Run(iris.Addr("localhost:3001"))
} // don't forget to look ../jwt_test.go to seee how to set your own custom claims
