package utils

import (
	"fmt"
	"log"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	alf "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	access_loggers "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	ext_http "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/google/uuid"
)

func GenerateSnapshots(config *XDSServerConfig, peers []*Peer, services []*Service) *cache.Snapshot {
	var clusters []types.Resource
	var routes []types.Resource
	var listeners []types.Resource
	var secrets []types.Resource

	for _, peer := range peers {
		if peer.Id == config.Peer.Id {
			listeners = append(listeners, makeLocalPeerListener(config, peer))
			routes = append(routes, makeLocalPeerRouteConfig(config, services))
		} else {
			clusters = append(clusters, makeRemotePeerCluster(config, peer))
		}
		secrets = append(secrets, makeSecrets(peer)...)
	}

	for _, service := range services {
		if service.PeerId == config.Peer.Id {
			clusters = append(clusters, makeLocalServiceCluster(service))
		} else {
			listeners = append(listeners, makeRemoteServiceListener(service))
		}
	}

	secrets = append(secrets, makeDefaultSecrets(config)...)

	snapshot, _ := cache.NewSnapshot(uuid.New().String(), map[resource.Type][]types.Resource{
		resource.ClusterType:  clusters,
		resource.RouteType:    routes,
		resource.ListenerType: listeners,
		resource.SecretType:   secrets,
	})

	return snapshot
}

func makeLocalPeerListener(config *XDSServerConfig, peer *Peer) *listener.Listener {
	name := fmt.Sprintf("peer-%s", peer.Id)
	routerConfig, _ := anypb.New(&router.Router{})

	stdoutAccessLog, err := anypb.New(&access_loggers.StdoutAccessLog{})
	if err != nil {
		panic(err)
	}

	manager := &hcm.HttpConnectionManager{
		StatPrefix: name,
		HttpFilters: []*hcm.HttpFilter{{
			Name:       wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
		}},
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    configSource("ads", ""),
				RouteConfigName: name,
			},
		},
		AccessLog: []*alf.AccessLog{{
			Name: "envoy.access_loggers.stdout",
			ConfigType: &alf.AccessLog_TypedConfig{
				TypedConfig: stdoutAccessLog,
			},
		},
		},
	}

	pbst, err := anypb.New(manager)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	var transportSocket *core.TransportSocket
	if config.Secret.Enabled {
		transportSocket = makeTransportSocketForDownstream(config, peer)
	}

	filterChains := []*listener.FilterChain{
		{
			Filters: []*listener.Filter{
				{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: pbst,
					},
				},
			},
			TransportSocket: transportSocket,
		},
	}

	return makeListener(name, peer.Port, filterChains)
}

func makeTransportSocketForDownstream(config *XDSServerConfig, peer *Peer) *core.TransportSocket {
	tlsRootCaName := config.Secret.TlsRootCaDefaultName
	if peer.tlsRootCa != "" {
		tlsRootCaName = fmt.Sprintf("tls-root-ca-%s", peer.Id)
	}

	tlsPrivateCaName := config.Secret.TlsPrivateCaDefaultName
	if peer.tlsPrivateKey != "" && peer.tlsPrivateCa != "" {
		tlsPrivateCaName = fmt.Sprintf("tls-private-ca-%s", peer.Id)
	}

	sdsConfig := configSource("xds", config.Secret.SdsConfigClusterName)

	tlsc := &auth.DownstreamTlsContext{
		RequireClientCertificate: &wrapperspb.BoolValue{
			Value: true,
		},
		CommonTlsContext: &auth.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{{
				Name:      tlsPrivateCaName,
				SdsConfig: sdsConfig,
			}},
			ValidationContextType: &auth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
					Name:      tlsRootCaName,
					SdsConfig: sdsConfig,
				},
			},
		}}

	mt, _ := anypb.New(tlsc)
	return &core.TransportSocket{
		Name: wellknown.TransportSocketTLS,
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: mt,
		},
	}
}

func makeLocalPeerRouteConfig(config *XDSServerConfig, services []*Service) *route.RouteConfiguration {
	var virtualHosts []*route.VirtualHost
	for _, service := range services {
		if service.PeerId != config.Peer.Id {
			continue
		}
		virtualHosts = append(virtualHosts, makeVirtualHostWithConnectMatcher(service.Host))
		if service.Mode == "http" {
			name := fmt.Sprintf("%s.http", service.Host)
			virtualHosts = append(virtualHosts, makeVirtualHostWithPrefix(name, service.Host))
		}
	}

	return &route.RouteConfiguration{
		Name:         fmt.Sprintf("peer-%s", config.Peer.Id),
		VirtualHosts: virtualHosts,
	}
}

func makeRemotePeerCluster(config *XDSServerConfig, peer *Peer) *cluster.Cluster {
	name := fmt.Sprintf("peer-%s", peer.Id)

	var transportSocket *core.TransportSocket
	if config.Secret.Enabled {
		transportSocket = makeTransportSocketForUpstream(config, peer)
	}

	return &cluster.Cluster{
		Name:                          name,
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		DnsLookupFamily:               cluster.Cluster_V4_ONLY,
		TypedExtensionProtocolOptions: makeTypedExtensionProtocolOptions(peer.Mode),
		LoadAssignment:                makeEndpoint(name, peer.Host, peer.Port),
		TransportSocket:               transportSocket,
	}
}

func makeTransportSocketForUpstream(config *XDSServerConfig, peer *Peer) *core.TransportSocket {
	tlsRootCaName := config.Secret.TlsRootCaDefaultName
	if peer.tlsRootCa != "" {
		tlsRootCaName = fmt.Sprintf("tls-root-ca-%s", peer.Id)
	}

	tlsPrivateCaName := config.Secret.TlsPrivateCaDefaultName
	if peer.tlsPrivateKey != "" && peer.tlsPrivateCa != "" {
		tlsPrivateCaName = fmt.Sprintf("tls-private-ca-%s", peer.Id)
	}

	sdsConfig := configSource("xds", config.Secret.SdsConfigClusterName)

	tlsc := &auth.UpstreamTlsContext{
		CommonTlsContext: &auth.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{{
				Name:      tlsPrivateCaName,
				SdsConfig: sdsConfig,
			}},
			ValidationContextType: &auth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
					Name:      tlsRootCaName,
					SdsConfig: sdsConfig,
				},
			},
		},
	}

	mt, _ := anypb.New(tlsc)
	return &core.TransportSocket{
		Name: wellknown.TransportSocketTLS,
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: mt,
		},
	}
}

func makeLocalServiceCluster(service *Service) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                          service.Host,
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		DnsLookupFamily:               cluster.Cluster_V4_ONLY,
		TypedExtensionProtocolOptions: makeTypedExtensionProtocolOptions(service.Mode),
		LoadAssignment:                makeEndpoint(service.Host, service.Host, service.TargetPort),
	}
}

func makeRemoteServiceListener(service *Service) *listener.Listener {
	name := fmt.Sprintf("peer-%s", service.PeerId)
	stdoutAccessLog, err := anypb.New(&access_loggers.StdoutAccessLog{})
	if err != nil {
		panic(err)
	}

	config := &tcp.TcpProxy{
		StatPrefix: service.Host,
		ClusterSpecifier: &tcp.TcpProxy_Cluster{
			Cluster: name,
		},
		TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
			Hostname: service.Host,
		},
		AccessLog: []*alf.AccessLog{{
			Name: "envoy.access_loggers.stdout",
			ConfigType: &alf.AccessLog_TypedConfig{
				TypedConfig: stdoutAccessLog,
			},
		},
		},
	}
	pbst, err := anypb.New(config)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	filterChains := []*listener.FilterChain{
		{
			Filters: []*listener.Filter{
				{
					Name: wellknown.TCPProxy,
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: pbst,
					},
				},
			},
		},
	}

	return makeListener(service.Host, service.Port, filterChains)
}

func makeVirtualHostWithConnectMatcher(name string) *route.VirtualHost {
	return &route.VirtualHost{
		Name:    name,
		Domains: []string{name},
		Routes: []*route.Route{{
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_ConnectMatcher_{},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: name,
					},
					UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
						UpgradeType:   "CONNECT",
						ConnectConfig: &route.RouteAction_UpgradeConfig_ConnectConfig{},
					}},
				},
			},
		}},
	}
}

func makeVirtualHostWithPrefix(name string, cluster string) *route.VirtualHost {
	return &route.VirtualHost{
		Name:    name,
		Domains: []string{"*"},
		Routes: []*route.Route{{
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: "/",
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: cluster,
					},
				},
			},
		}},
	}
}

func makeSecrets(peer *Peer) []types.Resource {
	var secrets []types.Resource
	if peer.tlsRootCa != "" {
		rootCaName := fmt.Sprintf("tls-root-ca-%s", peer.Id)
		rootCaSecret := MakeRootCaSecret(rootCaName, peer.tlsRootCa)
		secrets = append(secrets, rootCaSecret)
	}

	if peer.tlsPrivateKey != "" && peer.tlsPrivateCa != "" {
		tlsPrivateCaName := fmt.Sprintf("tls-private-ca-%s", peer.Id)
		tlsPrivateCaSecret := MakePrivateCaSecret(tlsPrivateCaName, peer.tlsPrivateKey, peer.tlsPrivateCa)
		secrets = append(secrets, tlsPrivateCaSecret)
	}
	return secrets
}

func makeDefaultSecrets(config *XDSServerConfig) []types.Resource {
	var secrets []types.Resource
	tlsRootCaDefaultSecret := MakeRootCaSecret(config.Secret.TlsRootCaDefaultName, config.Secret.DefaultRootCa)
	secrets = append(secrets, tlsRootCaDefaultSecret)
	tlsPrivateCaDefaultSecret := MakePrivateCaSecret(config.Secret.TlsPrivateCaDefaultName, config.Secret.DefaultPrivateKey, config.Secret.DefaultPrivateCa)
	secrets = append(secrets, tlsPrivateCaDefaultSecret)
	return secrets
}

func makeListener(name string, port uint32, filterChains []*listener.FilterChain) *listener.Listener {
	return &listener.Listener{
		Name: name,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: filterChains,
	}
}

func makeTypedExtensionProtocolOptions(mode string) map[string]*anypb.Any {
	var httpProtocolOptions *anypb.Any
	var err error
	if mode == "tcp" {
		httpProtocolOptions, err = anypb.New(&ext_http.HttpProtocolOptions{
			UpstreamProtocolOptions: &ext_http.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &ext_http.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &ext_http.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: &core.Http2ProtocolOptions{},
					},
				},
			},
		})
	}

	if httpProtocolOptions == nil && err != nil {
		panic(err)
	}

	if httpProtocolOptions == nil {
		return nil
	}

	return map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": httpProtocolOptions,
	}
}

func makeEndpoint(clusterName string, host string, port uint32) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  host,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: port,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func configSource(mode, xdsCluster string) *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	switch mode {
	case "ads":
		source.ConfigSourceSpecifier = &core.ConfigSource_Ads{
			Ads: &core.AggregatedConfigSource{},
		}
	case "xds":
		source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
			ApiConfigSource: &core.ApiConfigSource{
				TransportApiVersion:       resource.DefaultAPIVersion,
				ApiType:                   core.ApiConfigSource_GRPC,
				SetNodeOnFirstMessageOnly: true,
				GrpcServices: []*core.GrpcService{{
					TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: xdsCluster},
					},
				}},
			},
		}
	}
	return source
}
