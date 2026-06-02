# ADR 0004: Event bus with closure-captured type dispatch

- **Status:** Accepted
- **Date:** 2026-05-27
- **Related:** [`FLOW_EVENTS.md`](../internal/FLOW_EVENTS.md), [`CONTEXT.md`](../internal/CONTEXT.md#event-bus)

## Context

Features need to react to events emitted by other features without tight coupling:

- The policy controller needs to know when a `VaultConnection` becomes `Active` so it can dequeue waiting reconciles.
- Tokens need to be invalidated when their backing connection rotates.
- Metrics and telemetry want to count "sync" events centrally.

A direct method call would couple features. Channels alone don't carry type information; reflection would work but adds per-event overhead in the dispatch path.

## Decision

Implement a typed in-process event bus at [`shared/events/`](../../shared/events/) with **closure-captured handlers**:

```go
type EventBus struct {
    handlers map[reflect.Type][]func(any) // any → assert at registration time
}

func Subscribe[T Event](bus *EventBus, handler func(T)) {
    t := reflect.TypeOf(*new(T))
    bus.handlers[t] = append(bus.handlers[t], func(v any) {
        handler(v.(T))  // <-- type assertion captured in closure
    })
}

func Publish[T Event](bus *EventBus, event T) {
    for _, h := range bus.handlers[reflect.TypeOf(event)] {
        h(event)  // no further type switch needed
    }
}
```

The type assertion happens **once at subscribe time** (captured in the closure), not on every publish. The dispatch loop is then a plain function call — no `switch v.(type)` block.

`PublishAsync[T]` spawns a goroutine per handler for fire-and-forget propagation. Buffered channels are used by tests that need synchronization.

## Consequences

### Positive

- **Type-safe** — `Subscribe(bus, func(e PolicySynced) {...})` is a compile-time check; the bus stays generic.
- **Hot path is fast** — one map lookup + a slice of plain function calls; no type switch on dispatch.
- **Extensible** — new event types add a new key to `handlers`; existing code doesn't change.

### Negative

- The implementation uses `reflect.TypeOf` for the map key. This is fine for our event volume (low-throughput operator events, not high-fanout telemetry) but would not scale to millions/sec.
- Tests using `PublishAsync` need careful synchronization. Standard pattern: handlers write to a buffered channel; test reads with timeout. Forgetting the buffer leads to flaky tests.

### Neutral

- The bus is **in-process only**. We do not propagate events across operator instances (leader-elected controllers). This is intentional — cross-instance signaling should go through K8s objects (status conditions, ConfigMaps), not in-memory buses.

## Alternatives considered

### Alternative A: `chan` per event type

Each event type gets its own typed channel; features subscribe by reading from the channel. Rejected — channels don't support multiple subscribers cleanly, and lifecycle/cleanup gets tangled.

### Alternative B: External pub-sub (NATS, Redis, etc.)

Overkill for in-process coordination; introduces a dependency the operator currently doesn't need.

### Alternative C: Direct method calls via wired-in dependencies

Tightly couples features. The whole point of the bus is to allow new features to subscribe without changing existing ones.

## References

- Implementation: [`shared/events/bus.go`](../../shared/events/bus.go)
- Event types: [`shared/events/connection.go`](../../shared/events/), [`policy.go`](../../shared/events/policy.go), [`role.go`](../../shared/events/role.go), [`token.go`](../../shared/events/token.go)
- Test pattern: see any `*_test.go` that uses `PublishAsync` — note the buffered channel sync primitive.
