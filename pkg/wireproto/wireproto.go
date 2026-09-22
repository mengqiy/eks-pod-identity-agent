// Package wireproto is the single place the agent names the wire types of the
// two protocols the workload identity path speaks: the SPIFFE Workload API and
// the Envoy Secret Discovery Service.
//
// At launch the generated Go for both comes from upstream modules,
// github.com/spiffe/go-spiffe/v2 and github.com/envoyproxy/go-control-plane/envoy.
// Taking them directly is the shortest path to a working handler. It costs
// binary size and pulls github.com/cncf/xds/go,
// github.com/envoyproxy/protoc-gen-validate and github.com/planetscale/vtprotobuf
// into the module graph for a handful of messages, and a later task replaces
// them with a pruned proto subset that has identical wire output.
//
// This package is what keeps that replacement contained. Every alias below is a
// target to repoint; the handlers import this package and never the upstream
// modules, so the swap is an edit of this file rather than a rewrite of every
// handler. TestRestrictedModules_AreImportedOnlyFromWireproto in the repository
// root enforces the rule.
//
// The generated registration functions are bound to variables at the bottom of the
// file rather than called at the wiring site, since Go has no function aliases. That
// keeps the import boundary at exactly one package with no exemptions. The service
// interfaces and the UnimplementedXxxServer structs do alias, contrary to what the
// task assumed: an alias denotes the same type, so a handler embedding
// UnimplementedSpiffeWorkloadAPIServer still satisfies SpiffeWorkloadAPIServer
// without naming anything upstream.
//
// google.golang.org/grpc and google.golang.org/protobuf are deliberately not
// part of the boundary. They survive the proto swap untouched, so a handler
// imports grpc for its stream types and anypb or structpb for the well-known
// types it has to construct.
//
// Only the server halves of both services are here, because that is all a handler
// needs. A test that drives the socket with a generated client needs the client
// constructors wrapped in this file too, the way the registration functions are;
// whoever writes that test adds them here rather than importing upstream.
package wireproto

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
)

// SPIFFE Workload API, from github.com/spiffe/go-spiffe/v2/proto/spiffe/workload.
//
// Every message on SpiffeWorkloadAPIServer is aliased, including the ones the
// agent answers Unimplemented for, so a handler can be written against the whole
// interface without reaching upstream.
type (
	// X509SVIDRequest is the request of FetchX509SVID and carries no fields.
	X509SVIDRequest = workload.X509SVIDRequest
	// X509SVIDResponse is one push on the FetchX509SVID stream.
	X509SVIDResponse = workload.X509SVIDResponse
	// X509SVID is a per-SVID entry inside X509SVIDResponse.Svids, carrying the
	// chain as DER leaf first, the key as PKCS#8 DER, and the trust bundle as
	// concatenated DER.
	//
	// It is not workloadidentity.X509SVID, which is the agent's own domain type
	// holding a crypto.Signer instead of key bytes. A handler translates between
	// the two, and a file that names both has to qualify both.
	X509SVID = workload.X509SVID
	// X509BundlesRequest is the request of FetchX509Bundles and carries no fields.
	X509BundlesRequest = workload.X509BundlesRequest
	// X509BundlesResponse is one push on the FetchX509Bundles stream.
	X509BundlesResponse = workload.X509BundlesResponse

	// JWTSVIDRequest is the request of the unary FetchJWTSVID.
	JWTSVIDRequest = workload.JWTSVIDRequest
	// JWTSVIDResponse is the response of FetchJWTSVID.
	JWTSVIDResponse = workload.JWTSVIDResponse
	// JWTSVID is a per-SVID entry inside JWTSVIDResponse.Svids. As with
	// X509SVID, the agent's domain type of the same name is a different type.
	JWTSVID = workload.JWTSVID
	// JWTBundlesRequest is the request of FetchJWTBundles and carries no fields.
	JWTBundlesRequest = workload.JWTBundlesRequest
	// JWTBundlesResponse is one push on the FetchJWTBundles stream, carrying one
	// JWK Set per trust domain.
	JWTBundlesResponse = workload.JWTBundlesResponse

	// ValidateJWTSVIDRequest is the request of the unary ValidateJWTSVID.
	ValidateJWTSVIDRequest = workload.ValidateJWTSVIDRequest
	// ValidateJWTSVIDResponse carries the validated token's claims as a
	// *structpb.Struct, which is built with structpb.NewStruct. That is a
	// function, so a handler populating Claims imports
	// google.golang.org/protobuf/types/known/structpb itself.
	ValidateJWTSVIDResponse = workload.ValidateJWTSVIDResponse

	// WITSVIDRequest is on the interface and the agent issues no WIT-SVIDs.
	// Aliased so an Unimplemented method can name its argument without an
	// upstream import.
	WITSVIDRequest = workload.WITSVIDRequest
	// WITSVIDResponse is the WIT-SVID stream message the agent never sends.
	WITSVIDResponse = workload.WITSVIDResponse
	// WITSVID is a per-SVID entry inside WITSVIDResponse.Svids.
	WITSVID = workload.WITSVID
	// WITBundlesRequest is on the interface and unimplemented, as above.
	WITBundlesRequest = workload.WITBundlesRequest
	// WITBundlesResponse is the WIT bundle stream message the agent never sends.
	WITBundlesResponse = workload.WITBundlesResponse

	// SpiffeWorkloadAPIServer is the service interface a Workload API handler
	// implements.
	SpiffeWorkloadAPIServer = workload.SpiffeWorkloadAPIServer
	// UnimplementedSpiffeWorkloadAPIServer has to be embedded by value in a
	// Workload API handler: the interface requires an unexported method that only
	// this struct provides, and RegisterWorkloadAPIServer panics on a nil pointer
	// embed.
	UnimplementedSpiffeWorkloadAPIServer = workload.UnimplementedSpiffeWorkloadAPIServer
)

// Envoy SDS: the service from service/secret/v3, the xDS envelope from
// service/discovery/v3, and the payload from
// extensions/transport_sockets/tls/v3 and config/core/v3.
type (
	// SecretDiscoveryServiceServer is the service interface an SDS handler
	// implements.
	SecretDiscoveryServiceServer = secretv3.SecretDiscoveryServiceServer
	// UnimplementedSecretDiscoveryServiceServer is optional to embed, because
	// this service is generated without the mustEmbed guard, and worth embedding
	// anyway: DeltaSecrets is on the interface and the agent does not serve it.
	UnimplementedSecretDiscoveryServiceServer = secretv3.UnimplementedSecretDiscoveryServiceServer
	// SDSStreamSecretsServer is the stream of the StreamSecrets RPC. This
	// generated code predates the generic stream types, so unlike the Workload
	// API there is a named interface to alias.
	SDSStreamSecretsServer = secretv3.SecretDiscoveryService_StreamSecretsServer
	// SDSDeltaSecretsServer is the stream of the DeltaSecrets RPC.
	SDSDeltaSecretsServer = secretv3.SecretDiscoveryService_DeltaSecretsServer

	// DiscoveryRequest is an xDS request, which for SDS names the secrets Envoy
	// wants in ResourceNames.
	DiscoveryRequest = discoveryv3.DiscoveryRequest
	// DiscoveryResponse is an xDS response. Its Resources field is []*anypb.Any,
	// packed with anypb.New, so a handler imports
	// google.golang.org/protobuf/types/known/anypb itself.
	DiscoveryResponse = discoveryv3.DiscoveryResponse
	// DeltaDiscoveryRequest is the incremental xDS request.
	DeltaDiscoveryRequest = discoveryv3.DeltaDiscoveryRequest
	// DeltaDiscoveryResponse is the incremental xDS response.
	DeltaDiscoveryResponse = discoveryv3.DeltaDiscoveryResponse
	// Resource wraps one resource inside a DeltaDiscoveryResponse.
	Resource = discoveryv3.Resource
	// Node identifies the requesting Envoy on a DiscoveryRequest.
	Node = corev3.Node

	// Secret is the SDS payload, carrying either a certificate or a validation
	// context in its Type oneof.
	Secret = tlsv3.Secret
	// Secret_TlsCertificate is the oneof wrapper that puts a keypair in a Secret.
	// The oneof interface itself is unexported upstream and cannot be aliased;
	// nothing needs to name it, since a handler assigns
	// Secret.Type = &Secret_TlsCertificate{...}.
	Secret_TlsCertificate = tlsv3.Secret_TlsCertificate
	// Secret_ValidationContext is the oneof wrapper that puts trust material in a
	// Secret.
	Secret_ValidationContext = tlsv3.Secret_ValidationContext
	// TlsCertificate holds the chain and the private key, both as *DataSource.
	TlsCertificate = tlsv3.TlsCertificate
	// CertificateValidationContext holds the trust anchors in TrustedCa.
	CertificateValidationContext = tlsv3.CertificateValidationContext
	// DataSource is how Envoy is handed bytes, a file path, or an environment
	// variable.
	DataSource = corev3.DataSource
	// DataSource_InlineBytes is the oneof wrapper that carries the bytes inline,
	// which is the only form an SVID-serving SDS uses. Envoy wants PEM here,
	// while the Workload API types above are DER, so a handler encodes at the
	// edge.
	DataSource_InlineBytes = corev3.DataSource_InlineBytes
)

// Service names, for code that needs to name a service rather than implement
// one: the metadata gate's exemption list and any test building a method string
// by hand.
//
// They are vars rather than consts because upstream exposes them as fields of a
// generated grpc.ServiceDesc. Reading them from the descriptor rather than
// writing the strings out is what keeps them correct across the proto swap.
//
// Note the asymmetry: the Workload API service name is bare, so its methods are
// /SpiffeWorkloadAPI/FetchX509SVID, while SDS is fully qualified.
var (
	// WorkloadAPIServiceName is the gRPC service name of the SPIFFE Workload API.
	WorkloadAPIServiceName = workload.SpiffeWorkloadAPI_ServiceDesc.ServiceName
	// SDSServiceName is the gRPC service name of the Envoy Secret Discovery
	// Service.
	SDSServiceName = secretv3.SecretDiscoveryService_ServiceDesc.ServiceName
)

// SecretTypeURL is the type URL of an SDS resource carrying a Secret, for the
// TypeUrl field of a DiscoveryResponse.
//
// Upstream declares it in github.com/envoyproxy/go-control-plane's root module,
// which this agent does not depend on, so it is written out here rather than
// adding a module for one string. anypb.New derives the same value from the message
// descriptor, so prefer it for the per-resource Any and keep this for the response's
// TypeUrl, where there may be no resource to read it off. Nothing here checks the two
// agree; the SDS handler is where that is worth asserting, since it packs both.
const SecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// The generated registration functions, bound to package-level variables.
//
// A function cannot be aliased with the type keyword, so it is bound as a value
// instead, which is how sigs.k8s.io/controller-runtime's alias.go re-exports the
// functions of the packages it fronts. The effect is the same as an alias for every
// caller, and it keeps these two names inside the one package allowed to see the
// upstream modules: a handler registers itself through these and never imports
// go-spiffe or go-control-plane.
var (
	// RegisterWorkloadAPIServer registers a SPIFFE Workload API handler on a server.
	RegisterWorkloadAPIServer = workload.RegisterSpiffeWorkloadAPIServer

	// RegisterSecretDiscoveryServiceServer registers an Envoy SDS handler on a
	// server.
	RegisterSecretDiscoveryServiceServer = secretv3.RegisterSecretDiscoveryServiceServer
)
