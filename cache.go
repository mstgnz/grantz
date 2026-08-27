package grantz

import (
	"context"
	"sync"
	"time"
)

// Cache keeps resolved grants out of the database on the hot path.
//
// An authorization check runs on nearly every request, and resolving it means joining
// five tables. Without a cache the kit would add a query per request per permission,
// which is how authorization ends up being the reason people disable authorization.
//
// The interface is here so a multi-instance deployment can put Redis behind it. The
// default implementation is per-process, which means an invalidation on one instance
// does not reach the others; if that matters, use a shared cache or keep the TTL short.
type Cache interface {
	Get(ctx context.Context, userID int64) ([]Grant, bool)
	Set(ctx context.Context, userID int64, grants []Grant)
	Invalidate(ctx context.Context, userID int64)
	InvalidateAll(ctx context.Context)
}

type memoryCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[int64]memoryEntry
	// now is swappable so the expiry behaviour can be tested without sleeping.
	now func() time.Time
}

type memoryEntry struct {
	grants    []Grant
	expiresAt time.Time
}

// NewMemoryCache returns an in-process cache with the given TTL.
//
// Keep the TTL short enough that a permission change reaches users without a restart,
// and long enough that a busy endpoint is not re-resolving constantly. A minute or two
// is the usual answer. A TTL of zero disables caching, which is useful while debugging
// a permission that appears not to apply.
func NewMemoryCache(ttl time.Duration) Cache {
	return &memoryCache{
		ttl:     ttl,
		entries: make(map[int64]memoryEntry),
		now:     time.Now,
	}
}

func (c *memoryCache) Get(_ context.Context, userID int64) ([]Grant, bool) {
	if c.ttl <= 0 {
		return nil, false
	}
	c.mu.RLock()
	entry, ok := c.entries[userID]
	c.mu.RUnlock()
	if !ok || c.now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.grants, true
}

func (c *memoryCache) Set(_ context.Context, userID int64, grants []Grant) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.entries[userID] = memoryEntry{grants: grants, expiresAt: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

func (c *memoryCache) Invalidate(_ context.Context, userID int64) {
	c.mu.Lock()
	delete(c.entries, userID)
	c.mu.Unlock()
}

func (c *memoryCache) InvalidateAll(_ context.Context) {
	c.mu.Lock()
	c.entries = make(map[int64]memoryEntry)
	c.mu.Unlock()
}

// noopCache is used when a caller passes no cache and no TTL.
type noopCache struct{}

func (noopCache) Get(context.Context, int64) ([]Grant, bool) { return nil, false }
func (noopCache) Set(context.Context, int64, []Grant)        {}
func (noopCache) Invalidate(context.Context, int64)          {}
func (noopCache) InvalidateAll(context.Context)              {}
