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

func TestTime(t *testing.T) {
	w := time.Now().Round(time.Second)
	t.Log(w)
	w = w.UTC()
	t.Log(w)

	w = w.Round(time.Second)
	t.Log(w)

	now := w
	t.Log(now.Unix())

	du := time.Hour * 2
	t.Log(du)

	expiresAt := now.Add(du).Unix()
	t.Log(expiresAt)

	du1 := time.Unix(expiresAt, 0).Sub(now)
	t.Log(du1)

	assert.Equal(t, du1, du)
}

func TestClaims(t *testing.T) {
	claims := NewClaims(123456, time.Hour)
	assert.Nil(t, claims.Valid())
}
