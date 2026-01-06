package vault

import (
	"fmt"
	"sync"
)

// ClientCache provides a thread-safe cache for Vault clients
type ClientCache struct {
	clients map[string]*Client
	mu      sync.RWMutex
}

// NewClientCache creates a new ClientCache
func NewClientCache() *ClientCache {
	return &ClientCache{
		clients: make(map[string]*Client),
	}
}

// Get retrieves a client by connection name
func (c *ClientCache) Get(name string) (*Client, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	client, ok := c.clients[name]
	if !ok {
		return nil, fmt.Errorf("vault client for connection %q not found in cache", name)
	}
	return client, nil
}

// Set stores a client in the cache
func (c *ClientCache) Set(name string, client *Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	client.SetConnectionName(name)
	c.clients[name] = client
}

// Delete removes a client from the cache
func (c *ClientCache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.clients, name)
}

// Has checks if a client exists in the cache
func (c *ClientCache) Has(name string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.clients[name]
	return ok
}

// GetOrCreate retrieves an existing client or creates a new one using the provided factory
func (c *ClientCache) GetOrCreate(name string, factory func() (*Client, error)) (*Client, error) {
	// First try to get with read lock
	c.mu.RLock()
	if client, ok := c.clients[name]; ok {
		c.mu.RUnlock()
		return client, nil
	}
	c.mu.RUnlock()

	// Need to create - acquire write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if client, ok := c.clients[name]; ok {
		return client, nil
	}

	// Create new client
	client, err := factory()
	if err != nil {
		return nil, err
	}

	client.SetConnectionName(name)
	c.clients[name] = client
	return client, nil
}

// List returns all connection names in the cache
func (c *ClientCache) List() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	names := make([]string, 0, len(c.clients))
	for name := range c.clients {
		names = append(names, name)
	}
	return names
}

// Clear removes all clients from the cache
func (c *ClientCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.clients = make(map[string]*Client)
}

// Size returns the number of clients in the cache
func (c *ClientCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.clients)
}
