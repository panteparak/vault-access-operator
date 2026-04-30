/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package watches contains MapFuncs and predicates used by feature
// controllers to react to events on related CRDs (e.g. role reconcilers
// watching VaultPolicy create events, or policy reconcilers watching
// VaultConnection phase transitions).
//
// # Logger convention (IMPROVEMENTS §22)
//
// Functions in this package use `sigs.k8s.io/controller-runtime/pkg/log`
// (`log.FromContext(ctx)`) rather than `logr.FromContextOrDiscard(ctx)`.
// These two are functionally equivalent when the context carries a logger
// (the common case inside Reconcile), but diverge on the fallback path:
//
//   - `log.FromContext` falls back to the controller-runtime global logger.
//   - `logr.FromContextOrDiscard` falls back to a silent discard logger.
//
// MapFuncs run inside controller-runtime's event-dispatch loop, which does
// not always inject a request-scoped logger (it depends on controller
// version and options). We prefer the global fallback over silently
// discarding log output that may be diagnostically important when watch
// fan-out goes wrong.
//
// Feature handlers (called from `Reconcile`, where `BaseReconciler` always
// injects a scoped logger) use `logr.FromContextOrDiscard` — the discard
// fallback is unreachable in practice and avoids pulling in the
// controller-runtime log package there.
package watches
