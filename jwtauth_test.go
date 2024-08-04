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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJWT(t *testing.T) {

	claims := NewClaims(123456, time.Hour)

	token, err := Sign(claims)
	assert.Nil(t, err)
	t.Logf("token=%s", token)

	parsedClaims, err := Parse(token)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, claims.UserID, parsedClaims.UserID)
	assert.Equal(t, claims.ExpiresAt, parsedClaims.ExpiresAt)
}
