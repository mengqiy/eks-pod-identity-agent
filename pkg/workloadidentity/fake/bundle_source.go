package fake

import (
	"context"
	"crypto"
	"errors"
	"slices"
	"sync"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// AuthorityKey identifies one JWT verification key, and is what
// BundleSource.JWTAuthority is keyed and recorded by.
type AuthorityKey struct {
	// TrustDomain is the trust domain the key belongs to.
	TrustDomain string
	// KeyID is the JWK key ID within that trust domain.
	KeyID string
}

// ErrAuthorityNotFound is returned by BundleSource.JWTAuthority when the
// requested key is not in Authorities and no canned error or func is set. It is
// the fake's own sentinel rather than a member of the taxonomy in pkg/errors, so
// a test can tell a lookup miss in the fake apart from an error a real
// implementation would return.
var ErrAuthorityNotFound = errors.New("fake: no JWT authority for trust domain and key id")

// BundleSource is a fake workloadidentity.BundleSource. X509Bundles, JWTBundles
// and JWTAuthority each have their own canned value, canned error, canned func
// and call counter, because nothing about a real implementation makes them fail
// together. OwnTrustDomain is the exception: it has a canned value and a counter
// but no canned error and no canned func, because
// workloadidentity.BundleSource.OwnTrustDomain returns a bare string and so has
// no way to fail.
//
// Only the two context-taking methods go through the Gate. OwnTrustDomain and
// JWTAuthority take no ctx, so neither can park or honour cancellation:
// OwnTrustDomain only counts, and JWTAuthority counts and records the key it was
// asked for.
//
// Set the fields before the fake is used. Use SetTrustDomain, SetX509Bundles,
// SetJWTBundles and SetAuthorities to change the canned values and errors while
// the fake is live; the fields themselves are not safe to write once a call can be
// in flight.
//
// X509Func, JWTFunc and AuthorityFunc are construction-time only and have no
// setter, because a func that has to change mid-run can close over the test's own
// state and switch on that, which keeps the switch under the test's own lock
// instead of adding three more setters here.
type BundleSource struct {
	Gate

	// TrustDomain is returned by OwnTrustDomain.
	TrustDomain string

	// X509 is returned by X509Bundles when X509Func and X509Err are nil, as a
	// copy the caller cannot use to mutate the fake.
	X509 map[string][][]byte
	// X509Err, when non-nil and X509Func is nil, is returned by X509Bundles
	// together with a nil map.
	X509Err error
	// X509Func, when non-nil, wins over X509 and X509Err: X509Bundles returns
	// whatever it returns, uncopied.
	X509Func func(ctx context.Context) (map[string][][]byte, error)

	// JWT is returned by JWTBundles when JWTFunc and JWTErr are nil, as a copy
	// the caller cannot use to mutate the fake.
	JWT map[string][]byte
	// JWTErr, when non-nil and JWTFunc is nil, is returned by JWTBundles
	// together with a nil map.
	JWTErr error
	// JWTFunc, when non-nil, wins over JWT and JWTErr: JWTBundles returns
	// whatever it returns, uncopied.
	JWTFunc func(ctx context.Context) (map[string][]byte, error)

	// Authorities is the lookup table for JWTAuthority.
	Authorities map[AuthorityKey]crypto.PublicKey
	// AuthorityErr, when non-nil and AuthorityFunc is nil, is returned by
	// JWTAuthority for every key, together with a nil public key.
	AuthorityErr error
	// AuthorityFunc, when non-nil, wins over Authorities and AuthorityErr:
	// JWTAuthority returns whatever it returns.
	AuthorityFunc func(trustDomain, keyID string) (crypto.PublicKey, error)

	mu                  sync.Mutex
	ownTrustDomainCalls int
	x509BundlesCalls    int
	jwtBundlesCalls     int
	jwtAuthorityCalls   int
	authorityRequests   []AuthorityKey
}

// OwnTrustDomain returns TrustDomain. It takes no ctx, so it does not go through
// the Gate and only counts.
func (s *BundleSource) OwnTrustDomain() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ownTrustDomainCalls++
	return s.TrustDomain
}

// X509Bundles returns a copy of X509, the canned error, or whatever X509Func
// returns. The copy is deep enough that a caller cannot reach the fake's map, its
// per-domain slice, or its authority bytes.
//
// It goes through the Gate first, parking only while the Gate is closed, and
// returns the Gate's error unchanged. A call that arrives with a done ctx, or that
// is woken by ctx rather than by Release, is never counted. A parked call is not
// counted while it is parked; it counts itself once Release wakes it and it is
// next scheduled, which can be after Release has returned. Use WaitForBlocked to
// observe a parked call, and observe the call's own return before asserting on
// X509BundlesCalls.
func (s *BundleSource) X509Bundles(ctx context.Context) (map[string][][]byte, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.x509BundlesCalls++
	fn, bundles, err := s.X509Func, s.X509, s.X509Err
	if fn == nil && err == nil {
		bundles = copyX509Bundles(bundles)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx)
	}
	if err != nil {
		return nil, err
	}
	return bundles, nil
}

// JWTBundles returns a copy of JWT, the canned error, or whatever JWTFunc
// returns. The copy is deep enough that a caller cannot reach the fake's map or
// its JWK Set bytes.
//
// It goes through the Gate first, parking only while the Gate is closed, and
// returns the Gate's error unchanged. A call that arrives with a done ctx, or that
// is woken by ctx rather than by Release, is never counted. A parked call is not
// counted while it is parked; it counts itself once Release wakes it and it is
// next scheduled, which can be after Release has returned. Use WaitForBlocked to
// observe a parked call, and observe the call's own return before asserting on
// JWTBundlesCalls.
func (s *BundleSource) JWTBundles(ctx context.Context) (map[string][]byte, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.jwtBundlesCalls++
	fn, bundles, err := s.JWTFunc, s.JWT, s.JWTErr
	if fn == nil && err == nil {
		bundles = copyJWTBundles(bundles)
	}
	s.mu.Unlock()

	if fn != nil {
		return fn(ctx)
	}
	if err != nil {
		return nil, err
	}
	return bundles, nil
}

// JWTAuthority records the lookup and resolves it against AuthorityFunc,
// AuthorityErr, then Authorities, returning ErrAuthorityNotFound when all three
// leave the key unresolved. It takes no ctx, so it does not go through the Gate and
// never parks; it counts the call and records the key on every path, misses
// included.
func (s *BundleSource) JWTAuthority(trustDomain, keyID string) (crypto.PublicKey, error) {
	key := AuthorityKey{TrustDomain: trustDomain, KeyID: keyID}

	s.mu.Lock()
	s.jwtAuthorityCalls++
	s.authorityRequests = append(s.authorityRequests, key)
	fn, err := s.AuthorityFunc, s.AuthorityErr
	authority, found := s.Authorities[key]
	s.mu.Unlock()

	if fn != nil {
		return fn(trustDomain, keyID)
	}
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrAuthorityNotFound
	}
	return authority, nil
}

// OwnTrustDomainCalls reports how many times OwnTrustDomain has been called.
func (s *BundleSource) OwnTrustDomainCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ownTrustDomainCalls
}

// X509BundlesCalls reports how many times X509Bundles has run past the Gate. A
// call woken by Release is counted when it is next scheduled, not when Release
// returns.
func (s *BundleSource) X509BundlesCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.x509BundlesCalls
}

// JWTBundlesCalls reports how many times JWTBundles has run past the Gate. A
// call woken by Release is counted when it is next scheduled, not when Release
// returns.
func (s *BundleSource) JWTBundlesCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtBundlesCalls
}

// JWTAuthorityCalls reports how many times JWTAuthority has been called.
func (s *BundleSource) JWTAuthorityCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtAuthorityCalls
}

// AuthorityRequests returns a copy of the keys JWTAuthority was asked for, in
// call order, so it is safe to read while another goroutine is calling the fake.
func (s *BundleSource) AuthorityRequests() []AuthorityKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.authorityRequests)
}

// SetTrustDomain replaces the domain OwnTrustDomain returns while the fake is
// live.
func (s *BundleSource) SetTrustDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TrustDomain = domain
}

// SetX509Bundles replaces the canned X.509 authorities and error while the fake
// is live. The map is not copied on the way in, so the caller must not keep
// mutating it.
func (s *BundleSource) SetX509Bundles(bundles map[string][][]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.X509 = bundles
	s.X509Err = err
}

// SetJWTBundles replaces the canned JWK Set bytes and error while the fake is
// live. The map is not copied on the way in, so the caller must not keep mutating
// it.
func (s *BundleSource) SetJWTBundles(bundles map[string][]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.JWT = bundles
	s.JWTErr = err
}

// SetAuthorities replaces the JWTAuthority lookup table and canned error while
// the fake is live. The map is not copied on the way in, so the caller must not
// keep mutating it.
func (s *BundleSource) SetAuthorities(authorities map[AuthorityKey]crypto.PublicKey, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Authorities = authorities
	s.AuthorityErr = err
}

// copyX509Bundles copies a trust domain keyed set of DER authorities down to the
// bytes. A nil map copies to a nil map, so an unset canned value stays
// distinguishable from an empty one.
func copyX509Bundles(in map[string][][]byte) map[string][][]byte {
	if in == nil {
		return nil
	}
	out := make(map[string][][]byte, len(in))
	for domain, authorities := range in {
		if authorities == nil {
			out[domain] = nil
			continue
		}
		copied := make([][]byte, len(authorities))
		for i, der := range authorities {
			copied[i] = slices.Clone(der)
		}
		out[domain] = copied
	}
	return out
}

// copyJWTBundles copies a trust domain keyed set of JWK Set documents down to the
// bytes. A nil map copies to a nil map, so an unset canned value stays
// distinguishable from an empty one.
func copyJWTBundles(in map[string][]byte) map[string][]byte {
	if in == nil {
		return nil
	}
	out := make(map[string][]byte, len(in))
	for domain, jwks := range in {
		out[domain] = slices.Clone(jwks)
	}
	return out
}

var _ workloadidentity.BundleSource = &BundleSource{}
