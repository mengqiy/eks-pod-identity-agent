package fake

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// bundleSourceTestTimeout bounds every wait in this file, so a fake that never
// releases a parked call fails the test instead of hanging the suite.
const bundleSourceTestTimeout = 2 * time.Second

// bundleSourceOwnKey and bundleSourceFederatedKey are deterministic verification
// keys for the JWTAuthority lookup table.
var (
	bundleSourceOwnKey       = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()
	bundleSourceFederatedKey = ed25519.NewKeyFromSeed(bundleSourceSeed(0x02)).Public()
)

// bundleSourceSeed builds a distinct ed25519 seed so two test keys differ.
func bundleSourceSeed(b byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return seed
}

// bundleSourceX509Result is what an X509Bundles call running in another goroutine
// hands back to the test.
type bundleSourceX509Result struct {
	bundles map[string][][]byte
	err     error
}

// bundleSourceJWTResult is what a JWTBundles call running in another goroutine
// hands back to the test.
type bundleSourceJWTResult struct {
	bundles map[string][]byte
	err     error
}

func TestBundleSourceOwnTrustDomain_Called_ReturnsTrustDomainAndCounts(t *testing.T) {
	testCases := []struct {
		name     string
		source   *BundleSource
		expected string
	}{
		{
			name:     "zero value returns the empty trust domain",
			source:   &BundleSource{},
			expected: "",
		},
		{
			name:     "canned trust domain is returned",
			source:   &BundleSource{TrustDomain: "example.org"},
			expected: "example.org",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.OwnTrustDomain()).To(Equal(tc.expected))
			g.Expect(tc.source.OwnTrustDomain()).To(Equal(tc.expected))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(2))
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(0))
		})
	}
}

func TestBundleSourceX509Bundles_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("bundle unavailable")
	canned := map[string][][]byte{
		"example.org": {[]byte("own-authority-der")},
		"other.org":   {[]byte("federated-authority-der"), []byte("federated-authority-der-2")},
	}

	testCases := []struct {
		name        string
		source      *BundleSource
		expected    map[string][][]byte
		expectedErr error
	}{
		{
			name:     "zero value returns a nil map and no error",
			source:   &BundleSource{},
			expected: nil,
		},
		{
			name:     "canned bundles are returned",
			source:   &BundleSource{X509: canned},
			expected: canned,
		},
		{
			name:     "empty canned bundles stay distinguishable from nil",
			source:   &BundleSource{X509: map[string][][]byte{}},
			expected: map[string][][]byte{},
		},
		{
			name:        "canned error wins over canned bundles",
			source:      &BundleSource{X509: canned, X509Err: cannedErr},
			expectedErr: cannedErr,
		},
		{
			name: "func wins over canned bundles and canned error",
			source: &BundleSource{
				X509:    canned,
				X509Err: cannedErr,
				X509Func: func(_ context.Context) (map[string][][]byte, error) {
					return map[string][][]byte{"func.org": {[]byte("func-der")}}, nil
				},
			},
			expected: map[string][][]byte{"func.org": {[]byte("func-der")}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.X509Bundles(context.Background())

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				if tc.expected == nil {
					g.Expect(got).To(BeNil())
				} else {
					g.Expect(got).To(Equal(tc.expected))
				}
			}
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(1))
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(0))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(0))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTBundles_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("bundle unavailable")
	canned := map[string][]byte{
		"example.org": []byte(`{"keys":[{"kid":"own"}]}`),
		"other.org":   []byte(`{"keys":[{"kid":"federated"}]}`),
	}

	testCases := []struct {
		name        string
		source      *BundleSource
		expected    map[string][]byte
		expectedErr error
	}{
		{
			name:     "zero value returns a nil map and no error",
			source:   &BundleSource{},
			expected: nil,
		},
		{
			name:     "canned jwk sets are returned",
			source:   &BundleSource{JWT: canned},
			expected: canned,
		},
		{
			name:     "empty canned jwk sets stay distinguishable from nil",
			source:   &BundleSource{JWT: map[string][]byte{}},
			expected: map[string][]byte{},
		},
		{
			name:        "canned error wins over canned jwk sets",
			source:      &BundleSource{JWT: canned, JWTErr: cannedErr},
			expectedErr: cannedErr,
		},
		{
			name: "func wins over canned jwk sets and canned error",
			source: &BundleSource{
				JWT:    canned,
				JWTErr: cannedErr,
				JWTFunc: func(_ context.Context) (map[string][]byte, error) {
					return map[string][]byte{"func.org": []byte(`{"keys":[]}`)}, nil
				},
			},
			expected: map[string][]byte{"func.org": []byte(`{"keys":[]}`)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.JWTBundles(context.Background())

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				if tc.expected == nil {
					g.Expect(got).To(BeNil())
				} else {
					g.Expect(got).To(Equal(tc.expected))
				}
			}
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(1))
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(0))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(0))
			g.Expect(tc.source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTAuthority_CannedBehaviour_ReturnsThatBehaviour(t *testing.T) {
	cannedErr := errors.New("authority unavailable")
	funcKey := ed25519.NewKeyFromSeed(bundleSourceSeed(0x03)).Public()
	authorities := map[AuthorityKey]crypto.PublicKey{
		{TrustDomain: "example.org", KeyID: "own-kid"}:     bundleSourceOwnKey,
		{TrustDomain: "other.org", KeyID: "federated-kid"}: bundleSourceFederatedKey,
	}

	testCases := []struct {
		name        string
		source      *BundleSource
		trustDomain string
		keyID       string
		expected    crypto.PublicKey
		expectedErr error
	}{
		{
			name:        "zero value reports the key as not found",
			source:      &BundleSource{},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expectedErr: ErrAuthorityNotFound,
		},
		{
			name:        "known key resolves to its authority",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expected:    bundleSourceOwnKey,
		},
		{
			name:        "known key in a federated domain resolves to its authority",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "other.org",
			keyID:       "federated-kid",
			expected:    bundleSourceFederatedKey,
		},
		{
			name:        "key id missing from a known trust domain is not found",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "example.org",
			keyID:       "unknown-kid",
			expectedErr: ErrAuthorityNotFound,
		},
		{
			name:        "trust domain missing altogether is not found",
			source:      &BundleSource{Authorities: authorities},
			trustDomain: "unknown.org",
			keyID:       "own-kid",
			expectedErr: ErrAuthorityNotFound,
		},
		{
			name:        "canned error wins over the lookup table",
			source:      &BundleSource{Authorities: authorities, AuthorityErr: cannedErr},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expectedErr: cannedErr,
		},
		{
			name: "func wins over the lookup table and the canned error",
			source: &BundleSource{
				Authorities:  authorities,
				AuthorityErr: cannedErr,
				AuthorityFunc: func(_, _ string) (crypto.PublicKey, error) {
					return funcKey, nil
				},
			},
			trustDomain: "example.org",
			keyID:       "own-kid",
			expected:    funcKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tc.source.JWTAuthority(tc.trustDomain, tc.keyID)

			if tc.expectedErr != nil {
				g.Expect(err).To(MatchError(tc.expectedErr))
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
				g.Expect(got).To(Equal(tc.expected))
			}
			// The request is recorded and counted on every path, misses included.
			g.Expect(tc.source.JWTAuthorityCalls()).To(Equal(1))
			g.Expect(tc.source.AuthorityRequests()).To(Equal([]AuthorityKey{{
				TrustDomain: tc.trustDomain,
				KeyID:       tc.keyID,
			}}))
			g.Expect(tc.source.OwnTrustDomainCalls()).To(Equal(0))
			g.Expect(tc.source.X509BundlesCalls()).To(Equal(0))
			g.Expect(tc.source.JWTBundlesCalls()).To(Equal(0))
		})
	}
}

func TestBundleSourceJWTAuthority_CalledRepeatedly_CountsCallsAndRecordsKeysInOrder(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{Authorities: map[AuthorityKey]crypto.PublicKey{
		{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
	}}

	g.Expect(source.JWTAuthorityCalls()).To(Equal(0))
	g.Expect(source.AuthorityRequests()).To(BeEmpty())

	got, err := source.JWTAuthority("example.org", "own-kid")
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceOwnKey))

	got, err = source.JWTAuthority("other.org", "missing-kid")
	g.Expect(err).To(MatchError(ErrAuthorityNotFound))
	g.Expect(got).To(BeNil())

	got, err = source.JWTAuthority("example.org", "own-kid")
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceOwnKey))

	g.Expect(source.JWTAuthorityCalls()).To(Equal(3))
	g.Expect(source.AuthorityRequests()).To(Equal([]AuthorityKey{
		{TrustDomain: "example.org", KeyID: "own-kid"},
		{TrustDomain: "other.org", KeyID: "missing-kid"},
		{TrustDomain: "example.org", KeyID: "own-kid"},
	}))

	// AuthorityRequests hands back a copy, so a test mutating it cannot rewrite
	// the record.
	recorded := source.AuthorityRequests()
	recorded[0] = AuthorityKey{}
	g.Expect(source.AuthorityRequests()[0]).To(Equal(AuthorityKey{TrustDomain: "example.org", KeyID: "own-kid"}))
}

func TestBundleSourceX509Bundles_ReturnedMapMutated_NextCallIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	der := []byte("own-authority-der")
	source := &BundleSource{X509: map[string][][]byte{"example.org": {der}}}
	expected := map[string][][]byte{"example.org": {[]byte("own-authority-der")}}

	got, err := source.X509Bundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(expected))

	// Mutate every level the caller can reach: the map, the per-domain slice, and
	// the authority bytes.
	got["injected.org"] = [][]byte{[]byte("injected-der")}
	got["example.org"] = append(got["example.org"], []byte("appended-der"))
	got["example.org"][0][0] = 'X'

	again, err := source.X509Bundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(again).To(Equal(expected))
	g.Expect(source.X509).To(Equal(expected))
	g.Expect(der).To(Equal([]byte("own-authority-der")))
	g.Expect(source.X509BundlesCalls()).To(Equal(2))
}

func TestBundleSourceX509Bundles_DomainWithNilAuthorities_KeepsNilApartFromEmpty(t *testing.T) {
	g := NewWithT(t)

	// A trust domain the agent knows about but holds no authority for is a
	// different state from one holding an empty set, and the copy has to keep the
	// two apart or a test cannot assert on either.
	source := &BundleSource{X509: map[string][][]byte{
		"nil.example.org":   nil,
		"empty.example.org": {},
	}}

	got, err := source.X509Bundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(HaveLen(2))
	g.Expect(got).To(HaveKey("nil.example.org"))
	g.Expect(got["nil.example.org"]).To(BeNil())
	g.Expect(got["empty.example.org"]).ToNot(BeNil())
	g.Expect(got["empty.example.org"]).To(BeEmpty())
	g.Expect(source.X509BundlesCalls()).To(Equal(1))
}

func TestBundleSourceJWTBundles_ReturnedMapMutated_NextCallIsUnaffected(t *testing.T) {
	g := NewWithT(t)

	jwks := []byte(`{"keys":[{"kid":"own"}]}`)
	source := &BundleSource{JWT: map[string][]byte{"example.org": jwks}}
	expected := map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)}

	got, err := source.JWTBundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(expected))

	got["injected.org"] = []byte(`{"keys":[]}`)
	got["example.org"][0] = 'X'

	again, err := source.JWTBundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(again).To(Equal(expected))
	g.Expect(source.JWT).To(Equal(expected))
	g.Expect(jwks).To(Equal([]byte(`{"keys":[{"kid":"own"}]}`)))
	g.Expect(source.JWTBundlesCalls()).To(Equal(2))
}

func TestBundleSourceSetters_CalledWhileLive_ReplaceCannedBehaviour(t *testing.T) {
	g := NewWithT(t)

	x509Err := errors.New("x509 bundle unavailable")
	jwtErr := errors.New("jwt bundle unavailable")
	source := &BundleSource{}

	x509Bundles, err := source.X509Bundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(x509Bundles).To(BeNil())

	source.SetX509Bundles(map[string][][]byte{"example.org": {[]byte("own-authority-der")}}, nil)
	x509Bundles, err = source.X509Bundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(x509Bundles).To(Equal(map[string][][]byte{"example.org": {[]byte("own-authority-der")}}))

	source.SetX509Bundles(nil, x509Err)
	x509Bundles, err = source.X509Bundles(context.Background())
	g.Expect(err).To(MatchError(x509Err))
	g.Expect(x509Bundles).To(BeNil())

	jwtBundles, err := source.JWTBundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(jwtBundles).To(BeNil())

	source.SetJWTBundles(map[string][]byte{"example.org": []byte(`{"keys":[]}`)}, nil)
	jwtBundles, err = source.JWTBundles(context.Background())
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(jwtBundles).To(Equal(map[string][]byte{"example.org": []byte(`{"keys":[]}`)}))

	source.SetJWTBundles(nil, jwtErr)
	jwtBundles, err = source.JWTBundles(context.Background())
	g.Expect(err).To(MatchError(jwtErr))
	g.Expect(jwtBundles).To(BeNil())

	g.Expect(source.X509BundlesCalls()).To(Equal(3))
	g.Expect(source.JWTBundlesCalls()).To(Equal(3))
}

func TestBundleSourceSetTrustDomain_CalledWhileLive_ChangesTheNextOwnTrustDomain(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{TrustDomain: "example.org"}
	g.Expect(source.OwnTrustDomain()).To(Equal("example.org"))

	source.SetTrustDomain("rotated.org")
	g.Expect(source.OwnTrustDomain()).To(Equal("rotated.org"))

	source.SetTrustDomain("")
	g.Expect(source.OwnTrustDomain()).To(BeEmpty())

	g.Expect(source.OwnTrustDomainCalls()).To(Equal(3))
}

func TestBundleSourceSetAuthorities_CalledWhileLive_ReplacesLookupTableAndError(t *testing.T) {
	g := NewWithT(t)

	cannedErr := errors.New("authority unavailable")
	own := AuthorityKey{TrustDomain: "example.org", KeyID: "own-kid"}
	// rotated stands in for a key id that only appears after a bundle refresh.
	rotated := AuthorityKey{TrustDomain: "example.org", KeyID: "rotated-kid"}
	source := &BundleSource{Authorities: map[AuthorityKey]crypto.PublicKey{own: bundleSourceOwnKey}}

	got, err := source.JWTAuthority(rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(MatchError(ErrAuthorityNotFound))
	g.Expect(got).To(BeNil())

	source.SetAuthorities(map[AuthorityKey]crypto.PublicKey{rotated: bundleSourceFederatedKey}, nil)

	got, err = source.JWTAuthority(rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceFederatedKey))

	// The table is replaced rather than merged, so the key the old one held is
	// gone with it.
	got, err = source.JWTAuthority(own.TrustDomain, own.KeyID)
	g.Expect(err).To(MatchError(ErrAuthorityNotFound))
	g.Expect(got).To(BeNil())

	// A canned error set alongside a table wins over that table.
	source.SetAuthorities(map[AuthorityKey]crypto.PublicKey{rotated: bundleSourceFederatedKey}, cannedErr)
	got, err = source.JWTAuthority(rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(MatchError(cannedErr))
	g.Expect(got).To(BeNil())

	// Clearing the canned error puts the table back in charge.
	source.SetAuthorities(map[AuthorityKey]crypto.PublicKey{rotated: bundleSourceFederatedKey}, nil)
	got, err = source.JWTAuthority(rotated.TrustDomain, rotated.KeyID)
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(got).To(Equal(bundleSourceFederatedKey))

	g.Expect(source.JWTAuthorityCalls()).To(Equal(5))
	g.Expect(source.AuthorityRequests()).To(Equal([]AuthorityKey{rotated, rotated, own, rotated, rotated}))
}

func TestBundleSourceSetters_CalledConcurrentlyWithTheirReader_CountEveryRead(t *testing.T) {
	const (
		writers    = 8
		readers    = 8
		iterations = 50
	)

	// read reports what it observed rather than asserting, because a gomega
	// failure in a reader goroutine would leave the writers running.
	testCases := []struct {
		name  string
		set   func(s *BundleSource, i int)
		read  func(s *BundleSource) error
		calls func(s *BundleSource) int
	}{
		{
			name: "SetTrustDomain against OwnTrustDomain",
			set: func(s *BundleSource, i int) {
				s.SetTrustDomain(fmt.Sprintf("domain-%d.org", i))
			},
			read: func(s *BundleSource) error {
				// Every value the writers set, and the value the fake started
				// with, is one a reader may legitimately see.
				switch domain := s.OwnTrustDomain(); {
				case domain == "example.org", strings.HasPrefix(domain, "domain-"):
					return nil
				default:
					return fmt.Errorf("OwnTrustDomain returned %q, which no writer set", domain)
				}
			},
			calls: func(s *BundleSource) int { return s.OwnTrustDomainCalls() },
		},
		{
			name: "SetAuthorities against JWTAuthority",
			set: func(s *BundleSource, i int) {
				// Every table the writers set keeps own-kid, so the reader below
				// must resolve it whichever table it lands on.
				s.SetAuthorities(map[AuthorityKey]crypto.PublicKey{
					{TrustDomain: "example.org", KeyID: fmt.Sprintf("kid-%d", i)}: bundleSourceFederatedKey,
					{TrustDomain: "example.org", KeyID: "own-kid"}:                bundleSourceOwnKey,
				}, nil)
			},
			read: func(s *BundleSource) error {
				authority, err := s.JWTAuthority("example.org", "own-kid")
				if err != nil {
					return err
				}
				if got, ok := authority.(ed25519.PublicKey); !ok || !got.Equal(bundleSourceOwnKey) {
					return fmt.Errorf("JWTAuthority returned %v, want the own key", authority)
				}
				return nil
			},
			calls: func(s *BundleSource) int { return s.JWTAuthorityCalls() },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			source := &BundleSource{
				TrustDomain: "example.org",
				Authorities: map[AuthorityKey]crypto.PublicKey{
					{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
				},
			}

			// Each reader owns one slot, so collecting results needs no lock of
			// its own and cannot mask a race inside the fake.
			readErrs := make([]error, readers)
			var wg sync.WaitGroup
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < iterations; i++ {
						tc.set(source, w*iterations+i)
					}
				}(w)
			}
			for r := 0; r < readers; r++ {
				wg.Add(1)
				go func(r int) {
					defer wg.Done()
					for i := 0; i < iterations; i++ {
						if err := tc.read(source); err != nil && readErrs[r] == nil {
							readErrs[r] = err
						}
					}
				}(r)
			}
			wg.Wait()

			for _, err := range readErrs {
				g.Expect(err).To(Not(HaveOccurred()))
			}
			g.Expect(tc.calls(source)).To(Equal(readers * iterations))
		})
	}
}

func TestBundleSourceX509Bundles_GateBlocked_ReturnsCannedBundlesAfterRelease(t *testing.T) {
	g := NewWithT(t)

	expected := map[string][][]byte{"example.org": {[]byte("own-authority-der")}}
	source := &BundleSource{X509: map[string][][]byte{"example.org": {[]byte("own-authority-der")}}}
	source.Block()

	ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
	t.Cleanup(cancel)

	done := make(chan bundleSourceX509Result, 1)
	go func() {
		bundles, err := source.X509Bundles(ctx)
		done <- bundleSourceX509Result{bundles: bundles, err: err}
	}()

	g.Expect(source.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(source.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(source.X509BundlesCalls()).To(Equal(0))

	source.Release()

	var got bundleSourceX509Result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("X509Bundles did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.bundles).To(Equal(expected))
	g.Expect(source.X509BundlesCalls()).To(Equal(1))
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestBundleSourceJWTBundles_GateBlocked_ReturnsCannedBundlesAfterRelease(t *testing.T) {
	g := NewWithT(t)

	expected := map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)}
	source := &BundleSource{JWT: map[string][]byte{"example.org": []byte(`{"keys":[{"kid":"own"}]}`)}}
	source.Block()

	ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
	t.Cleanup(cancel)

	done := make(chan bundleSourceJWTResult, 1)
	go func() {
		bundles, err := source.JWTBundles(ctx)
		done <- bundleSourceJWTResult{bundles: bundles, err: err}
	}()

	g.Expect(source.WaitForBlocked(ctx, 1)).To(Succeed())
	g.Expect(source.Blocked()).To(Equal(1))
	g.Expect(done).To(Not(Receive()))
	g.Expect(source.JWTBundlesCalls()).To(Equal(0))

	source.Release()

	var got bundleSourceJWTResult
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("JWTBundles did not return after Release: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.bundles).To(Equal(expected))
	g.Expect(source.JWTBundlesCalls()).To(Equal(1))
	g.Expect(source.Blocked()).To(Equal(0))
}

func TestBundleSourceBundles_ParkedCallContextCancelled_ReturnsContextError(t *testing.T) {
	testCases := []struct {
		name  string
		call  func(ctx context.Context, s *BundleSource) (bool, error)
		calls func(s *BundleSource) int
	}{
		{
			name: "x509 bundles",
			call: func(ctx context.Context, s *BundleSource) (bool, error) {
				bundles, err := s.X509Bundles(ctx)
				return bundles == nil, err
			},
			calls: func(s *BundleSource) int { return s.X509BundlesCalls() },
		},
		{
			name: "jwt bundles",
			call: func(ctx context.Context, s *BundleSource) (bool, error) {
				bundles, err := s.JWTBundles(ctx)
				return bundles == nil, err
			},
			calls: func(s *BundleSource) int { return s.JWTBundlesCalls() },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			source := &BundleSource{
				X509: map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
				JWT:  map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
			}
			source.Block()

			waitCtx, cancelWait := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
			t.Cleanup(cancelWait)
			callCtx, cancelCall := context.WithCancel(context.Background())
			t.Cleanup(cancelCall)

			type result struct {
				nilBundles bool
				err        error
			}
			done := make(chan result, 1)
			go func() {
				nilBundles, err := tc.call(callCtx, source)
				done <- result{nilBundles: nilBundles, err: err}
			}()

			g.Expect(source.WaitForBlocked(waitCtx, 1)).To(Succeed())
			cancelCall()

			var got result
			select {
			case got = <-done:
			case <-waitCtx.Done():
				t.Fatalf("the call did not return after its context was cancelled: %v", waitCtx.Err())
			}

			g.Expect(got.err).To(MatchError(context.Canceled))
			g.Expect(got.nilBundles).To(BeTrue())
			g.Expect(tc.calls(source)).To(Equal(0))
			g.Expect(source.Blocked()).To(Equal(0))
		})
	}
}

func TestBundleSourceGateBlocked_MethodsWithoutContext_DoNotPark(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{
		TrustDomain: "example.org",
		Authorities: map[AuthorityKey]crypto.PublicKey{
			{TrustDomain: "example.org", KeyID: "own-kid"}: bundleSourceOwnKey,
		},
	}
	source.Block()
	t.Cleanup(source.Release)

	type result struct {
		trustDomain string
		authority   crypto.PublicKey
		err         error
	}
	done := make(chan result, 1)
	go func() {
		trustDomain := source.OwnTrustDomain()
		authority, err := source.JWTAuthority("example.org", "own-kid")
		done <- result{trustDomain: trustDomain, authority: authority, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), bundleSourceTestTimeout)
	t.Cleanup(cancel)

	var got result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatalf("OwnTrustDomain or JWTAuthority parked at a closed gate: %v", ctx.Err())
	}

	g.Expect(got.err).To(Not(HaveOccurred()))
	g.Expect(got.trustDomain).To(Equal("example.org"))
	g.Expect(got.authority).To(Equal(bundleSourceOwnKey))
	g.Expect(source.Blocked()).To(Equal(0))
	g.Expect(source.OwnTrustDomainCalls()).To(Equal(1))
	g.Expect(source.JWTAuthorityCalls()).To(Equal(1))
	g.Expect(source.AuthorityRequests()).To(Equal([]AuthorityKey{{TrustDomain: "example.org", KeyID: "own-kid"}}))
}

func TestBundleSourceBundles_ContextAlreadyDone_ReturnContextErrorWithoutParking(t *testing.T) {
	g := NewWithT(t)

	source := &BundleSource{
		X509: map[string][][]byte{"example.org": {[]byte("own-authority-der")}},
		JWT:  map[string][]byte{"example.org": []byte(`{"keys":[]}`)},
	}
	source.Block()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	x509Bundles, err := source.X509Bundles(ctx)
	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(x509Bundles).To(BeNil())

	jwtBundles, err := source.JWTBundles(ctx)
	g.Expect(err).To(MatchError(context.Canceled))
	g.Expect(jwtBundles).To(BeNil())

	g.Expect(source.X509BundlesCalls()).To(Equal(0))
	g.Expect(source.JWTBundlesCalls()).To(Equal(0))
	g.Expect(source.Blocked()).To(Equal(0))
}
