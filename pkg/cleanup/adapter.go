/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cleanup

import (
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// ClientCacheAdapter adapts *vault.ClientCache to the ClientCache interface.
type ClientCacheAdapter struct {
	cache *vault.ClientCache
}

// NewClientCacheAdapter creates a new adapter wrapping a vault.ClientCache.
func NewClientCacheAdapter(cache *vault.ClientCache) *ClientCacheAdapter {
	return &ClientCacheAdapter{cache: cache}
}

// Get retrieves a VaultClient by connection name.
func (a *ClientCacheAdapter) Get(name string) (VaultClient, error) {
	return a.cache.Get(name)
}
