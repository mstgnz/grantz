package grantz

import (
	"context"
	"sync"
	"time"
)

// CacheOf keeps resolved grants out of the database on the hot path.
//
// An authorization check runs on nearly every request, and resolving it means joining
// five tables. Without a cache the kit would add a query per request per permission,
// which is how authorization ends up being the reason people disable authorization.
//
// The interface is here so a multi-instance deployment can put Redis behind it. The
// default implementation is per-process, which means an invalidation on one instance
// does not reach the others; if that matters, use a shared cache or keep the TTL short.
type CacheOf[T comparable] interface {
	Get(ctx context.Context, userID T) ([]Grant, bool)
	Set(ctx context.Context, userID T, grants []Grant)
	Invalidate(ctx context.Context, userID T)
	InvalidateAll(ctx context.Context)
}

type memoryCache[T comparable] struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[T]memoryEntry
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
func NewMemoryCache(ttl time.Duration) Cache { return NewMemoryCacheOf[int64](ttl) }

// NewMemoryCacheOf is NewMemoryCache for a user id type other than int64.
func NewMemoryCacheOf[T comparable](ttl time.Duration) CacheOf[T] {
	return &memoryCache[T]{
		ttl:     ttl,
		entries: make(map[T]memoryEntry),
		now:     time.Now,
	}
}

func (c *memoryCache[T]) Get(_ context.Context, userID T) ([]Grant, bool) {
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

func (c *memoryCache[T]) Set(_ context.Context, userID T, grants []Grant) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.entries[userID] = memoryEntry{grants: grants, expiresAt: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

func (c *memoryCache[T]) Invalidate(_ context.Context, userID T) {
	c.mu.Lock()
	delete(c.entries, userID)
	c.mu.Unlock()
}

func (c *memoryCache[T]) InvalidateAll(_ context.Context) {
	c.mu.Lock()
	c.entries = make(map[T]memoryEntry)
	c.mu.Unlock()
}

// noopCache is used when a caller passes no cache and no TTL.
type noopCache[T comparable] struct{}

func (noopCache[T]) Get(context.Context, T) ([]Grant, bool) { return nil, false }
func (noopCache[T]) Set(context.Context, T, []Grant)        {}
func (noopCache[T]) Invalidate(context.Context, T)          {}
func (noopCache[T]) InvalidateAll(context.Context)          {}
