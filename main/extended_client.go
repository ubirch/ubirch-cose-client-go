// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"path"

	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
)

type ExtendedClient struct {
	clients.Client
	signingServiceURL string
}

func (c *ExtendedClient) sendToUbirchSigningService(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error) {
	endpoint := path.Join(c.signingServiceURL, uid.String(), "hash")
	return clients.Post(endpoint, upp, UCCHeader(auth))
}

func UCCHeader(auth string) map[string]string {
	return map[string]string{
		"x-auth-token": auth,
		"content-type": "application/octet-stream",
	}
}
