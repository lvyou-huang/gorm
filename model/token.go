package model

import "github.com/golang-jwt/jwt/v4"

type Custom_claims struct {
	Phoneoremail string `json:"phoneoremail"`
	Isadmin      bool   `json:"isadmin"`
	jwt.RegisteredClaims
}
