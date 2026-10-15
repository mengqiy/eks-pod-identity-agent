package handlers

import (
	"math"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// validWorkloadIdentityOpts returns options every field of which passes
// validation, so a case can change one field and attribute the failure to it.
// The values are the flag defaults.
func validWorkloadIdentityOpts() WorkloadIdentityServerOpts {
	return WorkloadIdentityServerOpts{
		ClusterName:         "cluster-a",
		X509SVIDDuration:    6 * time.Hour,
		JWTSVIDDuration:     time.Hour,
		SVIDRenewalFraction: 0.5,
		SVIDRenewalJitter:   0.1,
		MaxCacheSize:        2000,
		CredentialRetention: 3 * time.Hour,
	}
}

func TestValidate_DefaultValues_AreAccepted(t *testing.T) {
	g := NewWithT(t)

	g.Expect(validWorkloadIdentityOpts().Validate()).To(Succeed())
}

// TestValidate_SVIDDurations_AreBoundedByTheirEnvelopes covers both ends of both
// envelopes, since a lifetime outside its envelope is rejected by STS on every
// issuance and the point of checking it here is that the agent never boots with
// one.
func TestValidate_SVIDDurations_AreBoundedByTheirEnvelopes(t *testing.T) {
	testCases := []struct {
		name          string
		x509Duration  time.Duration
		jwtDuration   time.Duration
		expectedError string
	}{
		{
			name:         "both at the bottom of their envelopes",
			x509Duration: time.Hour,
			jwtDuration:  time.Minute,
		},
		{
			name:         "both at the top of their envelopes",
			x509Duration: 12 * time.Hour,
			jwtDuration:  time.Hour,
		},
		{
			name:          "x509 one nanosecond below its envelope",
			x509Duration:  time.Hour - time.Nanosecond,
			jwtDuration:   5 * time.Minute,
			expectedError: "--x509-svid-duration is 59m59.999999999s: a requested X.509-SVID lifetime has to be between 1h0m0s and 12h0m0s inclusive",
		},
		{
			name:          "x509 one nanosecond above its envelope",
			x509Duration:  12*time.Hour + time.Nanosecond,
			jwtDuration:   5 * time.Minute,
			expectedError: "--x509-svid-duration is 12h0m0.000000001s: a requested X.509-SVID lifetime has to be between 1h0m0s and 12h0m0s inclusive",
		},
		{
			name:          "jwt one nanosecond below its envelope",
			x509Duration:  6 * time.Hour,
			jwtDuration:   time.Minute - time.Nanosecond,
			expectedError: "--jwt-svid-duration is 59.999999999s: a requested JWT-SVID lifetime has to be between 1m0s and 1h0m0s inclusive",
		},
		{
			name:          "jwt one nanosecond above its envelope",
			x509Duration:  6 * time.Hour,
			jwtDuration:   time.Hour + time.Nanosecond,
			expectedError: "--jwt-svid-duration is 1h0m0.000000001s: a requested JWT-SVID lifetime has to be between 1m0s and 1h0m0s inclusive",
		},
		{
			// a duration flag left off the command line entirely still has a
			// default, so a zero here means an operator asked for zero
			name:          "x509 left at zero",
			x509Duration:  0,
			jwtDuration:   5 * time.Minute,
			expectedError: "--x509-svid-duration is 0s",
		},
		{
			name:          "jwt left at zero",
			x509Duration:  6 * time.Hour,
			jwtDuration:   0,
			expectedError: "--jwt-svid-duration is 0s",
		},
		{
			name:          "negative durations",
			x509Duration:  -time.Hour,
			jwtDuration:   -time.Minute,
			expectedError: "--x509-svid-duration is -1h0m0s",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			opts := validWorkloadIdentityOpts()
			opts.X509SVIDDuration = tc.x509Duration
			opts.JWTSVIDDuration = tc.jwtDuration

			err := opts.Validate()
			if tc.expectedError == "" {
				g.Expect(err).To(Succeed())
				return
			}
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(tc.expectedError))
		})
	}
}

func TestValidate_SVIDRenewal_KeepsTheRenewalBandInsideTheLifetime(t *testing.T) {
	testCases := []struct {
		name          string
		fraction      float64
		jitter        float64
		expectedError string
	}{
		{
			name:     "defaults renew in the band 0.45 to 0.55",
			fraction: 0.5,
			jitter:   0.1,
		},
		{
			name:     "jitter at zero is accepted, since a test wants a deterministic renewal point",
			fraction: 0.5,
			jitter:   0,
		},
		{
			name:     "jitter at its maximum with the default fraction",
			fraction: 0.5,
			jitter:   maxSVIDRenewalJitter,
		},
		{
			name:          "fraction at zero",
			fraction:      0,
			jitter:        0.1,
			expectedError: "--svid-renewal-fraction is 0: it has to be greater than 0 and less than 1",
		},
		{
			name:          "fraction at one",
			fraction:      1,
			jitter:        0.1,
			expectedError: "--svid-renewal-fraction is 1: it has to be greater than 0 and less than 1",
		},
		{
			name:          "fraction below zero",
			fraction:      -0.1,
			jitter:        0.1,
			expectedError: "--svid-renewal-fraction is -0.1",
		},
		{
			name:          "fraction above one",
			fraction:      1.1,
			jitter:        0.1,
			expectedError: "--svid-renewal-fraction is 1.1",
		},
		{
			name:          "fraction is NaN",
			fraction:      math.NaN(),
			jitter:        0.1,
			expectedError: "--svid-renewal-fraction is NaN",
		},
		{
			name:          "jitter below zero",
			fraction:      0.5,
			jitter:        -0.01,
			expectedError: "--svid-renewal-jitter is -0.01: it has to be between 0 and 0.5 inclusive",
		},
		{
			name:          "jitter above its maximum",
			fraction:      0.5,
			jitter:        maxSVIDRenewalJitter + 0.01,
			expectedError: "--svid-renewal-jitter is 0.51: it has to be between 0 and 0.5 inclusive",
		},
		{
			name:          "jitter is NaN",
			fraction:      0.5,
			jitter:        math.NaN(),
			expectedError: "--svid-renewal-jitter is NaN",
		},
		{
			// each value is inside its own range, but together they renew before
			// the credential is issued
			name:          "band reaches below issuance",
			fraction:      0.1,
			jitter:        0.4,
			expectedError: "renews between -0.1 and 0.30000000000000004 of the issued lifetime",
		},
		{
			// and here, after it has expired
			name:          "band reaches past expiry",
			fraction:      0.9,
			jitter:        0.4,
			expectedError: "renews between 0.7 and 1.1 of the issued lifetime",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			opts := validWorkloadIdentityOpts()
			opts.SVIDRenewalFraction = tc.fraction
			opts.SVIDRenewalJitter = tc.jitter

			err := opts.Validate()
			if tc.expectedError == "" {
				g.Expect(err).To(Succeed())
				return
			}
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(tc.expectedError))
		})
	}
}

// TestValidate_SeveralBadValues_AreAllReported proves the joined error rather
// than the first failure, so an operator fixing a config does not need one
// restart per bad flag.
func TestValidate_SeveralBadValues_AreAllReported(t *testing.T) {
	g := NewWithT(t)

	opts := WorkloadIdentityServerOpts{
		X509SVIDDuration:    24 * time.Hour,
		JWTSVIDDuration:     time.Second,
		SVIDRenewalFraction: 2,
		SVIDRenewalJitter:   3,
	}

	err := opts.Validate()
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("--" + FlagX509SVIDDuration))
	g.Expect(err.Error()).To(ContainSubstring("--" + FlagJWTSVIDDuration))
	g.Expect(err.Error()).To(ContainSubstring("--" + FlagSVIDRenewalFraction))
	g.Expect(err.Error()).To(ContainSubstring("--" + FlagSVIDRenewalJitter))
	g.Expect(err.Error()).To(ContainSubstring("--" + FlagMaxCacheSize))
	g.Expect(err.Error()).To(ContainSubstring("--" + FlagMaxCredentialRetention))
}

// TestValidate_CachingOff_IsRejected: the credentials path reads either caching
// flag at 0 as no cache, which workload identity can't run without. Negative
// values are rejected too, as the token minter already did.
func TestValidate_CachingOff_IsRejected(t *testing.T) {
	testCases := []struct {
		name      string
		size      int
		retention time.Duration
		flags     []string
	}{
		{name: "cache size 0", size: 0, retention: 3 * time.Hour, flags: []string{FlagMaxCacheSize}},
		{name: "negative cache size", size: -1, retention: 3 * time.Hour, flags: []string{FlagMaxCacheSize}},
		{name: "retention 0", size: 2000, retention: 0, flags: []string{FlagMaxCredentialRetention}},
		{name: "negative retention", size: 2000, retention: -time.Second, flags: []string{FlagMaxCredentialRetention}},
		{name: "both 0", size: 0, retention: 0, flags: []string{FlagMaxCacheSize, FlagMaxCredentialRetention}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			opts := validWorkloadIdentityOpts()
			opts.MaxCacheSize = tc.size
			opts.CredentialRetention = tc.retention

			err := opts.Validate()

			g.Expect(err).To(HaveOccurred())
			for _, flag := range tc.flags {
				g.Expect(err.Error()).To(ContainSubstring("--" + flag))
			}
			g.Expect(err.Error()).To(ContainSubstring("workload identity needs it positive"))
		})
	}
}

// TestSVIDDurationEnvelopes_MatchTheApiModel pins the envelopes to the numbers
// they were confirmed against. Widening one is a decision about what STS accepts
// and belongs in a review, not in a passing test.
func TestSVIDDurationEnvelopes_MatchTheApiModel(t *testing.T) {
	g := NewWithT(t)

	// sts:GetWorkloadIdentityCertificate MaxDurationSeconds: 3600 to 43200
	g.Expect(x509SVIDDurationEnvelope.min).To(Equal(time.Duration(3600) * time.Second))
	g.Expect(x509SVIDDurationEnvelope.max).To(Equal(time.Duration(43200) * time.Second))

	// sts:GetWebIdentityToken DurationSeconds: 60 to 3600
	g.Expect(jwtSVIDDurationEnvelope.min).To(Equal(time.Duration(60) * time.Second))
	g.Expect(jwtSVIDDurationEnvelope.max).To(Equal(time.Duration(3600) * time.Second))
}
