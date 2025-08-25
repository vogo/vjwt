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
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthClaims jwt claims
// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types
type AuthClaims struct {
	//  standard JWT claim which must contain an ID of the current application user
	Subject string `json:"sub,omitempty"`

	// Deprecated, use Subject instead
	// custom user id
	UserID int64 `json:"uid,omitempty"`

	// standard JWT claim that setting token expiration time
	// a UNIX timestamp in the future, in seconds, as integer
	ExpiresAt int64 `json:"exp,omitempty"`
}

// NewAuthClaims build
func NewAuthClaims(sub string, expires time.Duration) *AuthClaims {
	c := &AuthClaims{
		Subject:   sub,
		ExpiresAt: time.Now().Add(expires).Round(time.Second).Unix(),
	}
	c.UserID, _ = strconv.ParseInt(sub, 10, 64)
	return c
}

// NewClaims build
// Deprecated: use NewAuthClaims instead
func NewClaims(id int64, expires time.Duration) *AuthClaims {
	return &AuthClaims{
		UserID:    id,
		Subject:   strconv.FormatInt(id, 10),
		ExpiresAt: time.Now().Add(expires).Round(time.Second).Unix(),
	}
}

// GetExpirationTime implements the Claims interface.
func (c *AuthClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetNotBefore implements the Claims interface.
func (c *AuthClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuedAt implements the Claims interface.
func (c *AuthClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetAudience implements the Claims interface.
func (c *AuthClaims) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

// GetIssuer implements the Claims interface.
func (c *AuthClaims) GetIssuer() (string, error) {
	return "", nil
}

// GetSubject implements the Claims interface.
func (c *AuthClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// Valid time based claims
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c AuthClaims) Valid() error {
	now := time.Now().Round(time.Second).Unix()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now, false) {
		return jwt.ErrTokenExpired
	}

	return nil
}

// VerifyExpiresAt compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *AuthClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}
