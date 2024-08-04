// Author: wongoo
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package jwtauth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

var (
	signedKey                       = []byte("jwtauth")
	signingMethod jwt.SigningMethod = jwt.SigningMethodHS256
)

// SetKey of jwt
func SetKey(key []byte) {
	signedKey = key
}

// SetMethod of signing jwt
func SetMethod(method jwt.SigningMethod) {
	signingMethod = method
}

// Sign jwt token
func Sign(claims *AuthClaims) (string, error) {
	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString(signedKey)
}

func authKeyFunc(t *jwt.Token) (interface{}, error) {
	if t.Method != signingMethod {
		return nil, fmt.Errorf("unknown jwt token")
	}
	return signedKey, nil
}

// Parse jwt token
func Parse(jwtoken string) (*AuthClaims, error) {
	token, err := jwt.ParseWithClaims(jwtoken, &AuthClaims{}, authKeyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AuthClaims)
	if !ok {
		return nil, fmt.Errorf("not jwt claims")
	}
	err = claims.Valid()
	if err != nil {
		return nil, err
	}
	return claims, nil
}
