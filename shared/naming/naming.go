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

// Package naming centralizes derivation of Vault resource names (ADR 0010).
//
// Every Vault object the operator writes is named with a fixed 4-segment,
// dot-separated shape:
//
//	vao.{identity}.{namespace}.{name}
//
// "vao" marks the object as operator-managed at a glance in Vault listings.
// {identity} distinguishes clusters sharing one Vault CE server (which has no
// namespaces): --cluster-name when set, else the connection's auth mount
// (already unique per cluster — one cluster per mount, ADR 0008), else the
// placeholder. {namespace} is the CR namespace, or the placeholder for
// cluster-scoped CRs.
//
// The shape is injective: CR names may contain dots (RFC 1123 subdomain), so
// the name goes LAST and the arity is FIXED; segments 1–3 are dot-free by
// construction (validated flag charset, sanitized mount, RFC 1123 label
// namespaces), so two distinct CRs can never produce the same string.
package naming

import (
	"strings"
	"sync/atomic"
)

const (
	// Marker is the fixed first segment identifying operator-managed
	// Vault objects.
	Marker = "vao"
	// Placeholder fills an absent identity or namespace segment. It is
	// safe as a reserved token: "_" is an invalid RFC 1123 label (so no
	// namespace can equal it) and is rejected by --cluster-name
	// validation; Identity's sanitizer maps a bare-"_" mount to "-".
	Placeholder = "_"
	// separator joins segments. Dots are legal in Vault policy names
	// (only commas are not, being the token_policies list separator) and
	// in role names (single URL path segment).
	separator = "."
)

// ponytail: cluster is an operator-wide identity, set once at startup from
// --cluster-name and read-only thereafter. A package var avoids threading it
// through every adapter constructor and handler. atomic.Value keeps it
// race-clean. Ownership records and the root-logger tag also read it.
var cluster atomic.Value // holds string

// SetCluster records the operator's --cluster-name. Call once at startup,
// before the manager starts. Empty means "fall back to the auth mount".
func SetCluster(name string) { cluster.Store(name) }

// Cluster returns the configured cluster name ("" when unset).
func Cluster() string {
	name, _ := cluster.Load().(string)
	return name
}

// Identity resolves the identity segment: clusterName wins; else the
// sanitized auth mount; else Placeholder. Pure — callers pass Cluster()
// explicitly so per-connection mount fallback stays possible.
func Identity(clusterName, authMount string) string {
	if clusterName != "" {
		return clusterName
	}
	if m := sanitizeMount(authMount); m != "" {
		return m
	}
	return Placeholder
}

// sanitizeMount maps a mount path onto the dot-free segment charset
// [A-Za-z0-9_-]: every other rune (dots, slashes on nested mounts, …)
// becomes '-'. A result of exactly Placeholder becomes "-" so a mount
// literally named "_" cannot impersonate an absent identity.
func sanitizeMount(mount string) string {
	if mount == "" {
		return ""
	}
	s := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '_', r == '-':
			return r
		default:
			return '-'
		}
	}, mount)
	if s == Placeholder {
		return "-"
	}
	return s
}

// VaultName builds the fixed 4-segment Vault resource name. Pass namespace
// "" for cluster-scoped CRs (rendered as Placeholder). identity must come
// from Identity(); name is the CR metadata.name and may contain dots — it is
// the last segment, so the result stays unambiguous.
func VaultName(identity, namespace, name string) string {
	if namespace == "" {
		namespace = Placeholder
	}
	return Marker + separator + identity + separator + namespace + separator + name
}
