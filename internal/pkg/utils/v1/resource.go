package utils

import (
	"fmt"
	"log"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
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

	for _, peer := range peers {
		if peer.PartyId == config.Party.Id {
			listeners = append(listeners, makeHTTP2Listener(config, peer))
			routes = append(routes, makeRouteConfig(peer.PartyId, peer.Type, services))
		} else {
			clusters = append(clusters, makeClusterForPeer(config, peer))
		}
	}

	for _, service := range services {
		if service.PartyId != config.Party.Id {
			listeners = append(listeners, makeTCPListener(service))
		} else {
			clusters = append(clusters, makeClusterForService(service))
		}
	}

	snapshot, _ := cache.NewSnapshot(uuid.New().String(), map[resource.Type][]types.Resource{
		resource.ClusterType:  clusters,
		resource.RouteType:    routes,
		resource.ListenerType: listeners,
	})

	return snapshot
}

func makeHTTP2Listener(config *XDSServerConfig, peer *Peer) *listener.Listener {
	name := fmt.Sprintf("%s-%s", peer.Type, peer.PartyId)
	routerConfig, _ := anypb.New(&router.Router{})

	stdoutAccessLog, err := anypb.New(&access_loggers.StdoutAccessLog{})
	if err != nil {
		panic(err)
	}

	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_HTTP2,
		StatPrefix: peer.Type,
		HttpFilters: []*hcm.HttpFilter{{
			Name:       wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
		}},
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    configSource(),
				RouteConfigName: name,
			},
		},
		AccessLog: []*alf.AccessLog{{
			Name: wellknown.HTTPGRPCAccessLog,
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
			TransportSocket: makeTransportSocketForDownstream(config),
		},
	}

	return makeListener(name, peer.Port, filterChains)
}

func makeTCPListener(service *Service) *listener.Listener {
	name := fmt.Sprintf("%s-%s", service.Type, service.PartyId)
	stdoutAccessLog, err := anypb.New(&access_loggers.StdoutAccessLog{})
	if err != nil {
		panic(err)
	}

	config := &tcp.TcpProxy{
		StatPrefix: service.Type,
		ClusterSpecifier: &tcp.TcpProxy_Cluster{
			Cluster: name,
		},
		TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
			Hostname: service.Host,
		},
		AccessLog: []*alf.AccessLog{{
			Name: wellknown.HTTPGRPCAccessLog,
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
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: pbst,
					},
				},
			},
		},
	}

	return makeListener(service.Host, service.Port, filterChains)
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

func makeClusterForPeer(config *XDSServerConfig, peer *Peer) *cluster.Cluster {
	name := fmt.Sprintf("%s-%s", peer.Type, peer.PartyId)

	return &cluster.Cluster{
		Name:                          name,
		ConnectTimeout:                durationpb.New(5 * time.Second),
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		LbPolicy:                      cluster.Cluster_ROUND_ROBIN,
		DnsLookupFamily:               cluster.Cluster_V4_ONLY,
		TypedExtensionProtocolOptions: makeTypedExtensionProtocolOptions(),
		LoadAssignment:                makeEndpoint(name, peer.Host, peer.Port),
		TransportSocket:               makeTransportSocketForUpstream(config),
	}
}

func makeClusterForService(service *Service) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                          service.Host,
		ConnectTimeout:                durationpb.New(5 * time.Second),
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		LbPolicy:                      cluster.Cluster_ROUND_ROBIN,
		DnsLookupFamily:               cluster.Cluster_V4_ONLY,
		TypedExtensionProtocolOptions: makeTypedExtensionProtocolOptions(),
		LoadAssignment:                makeEndpoint(service.Host, service.Host, service.Port),
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

func makeRouteConfig(partyId string, type_ string, services []*Service) *route.RouteConfiguration {
	var virtualHosts []*route.VirtualHost
	for _, service := range services {
		if service.PartyId != partyId && service.Type == type_ {
			continue
		}
		virtualHosts = append(virtualHosts, &route.VirtualHost{
			Name:    service.Host,
			Domains: []string{service.Host},
			Routes: []*route.Route{{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_ConnectMatcher_{},
				},
				Action: &route.Route_Route{
					Route: &route.RouteAction{
						ClusterSpecifier: &route.RouteAction_Cluster{
							Cluster: service.Host,
						},
						UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
							UpgradeType:   "CONNECT",
							ConnectConfig: &route.RouteAction_UpgradeConfig_ConnectConfig{},
						}},
					},
				},
			}},
		})
	}

	return &route.RouteConfiguration{
		Name:         fmt.Sprintf("%s-%s", type_, partyId),
		VirtualHosts: virtualHosts,
	}
}

func makeTransportSocketForUpstream(config *XDSServerConfig) *core.TransportSocket {
	tlsc := &auth.UpstreamTlsContext{
		CommonTlsContext: &auth.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{{
				Name: config.Server.TlsCert,
			}},
			ValidationContextType: &auth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
					Name: config.Server.TlsValidationContext,
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

func makeTransportSocketForDownstream(config *XDSServerConfig) *core.TransportSocket {
	tlsc := &auth.DownstreamTlsContext{
		RequireClientCertificate: &wrapperspb.BoolValue{
			Value: true,
		},
		CommonTlsContext: &auth.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{{
				Name: config.Server.TlsCert,
			}},
			ValidationContextType: &auth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
					Name: config.Server.TlsValidationContext,
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

func configSource() *core.ConfigSource {
	return &core.ConfigSource{
		ResourceApiVersion: resource.DefaultAPIVersion,
		ConfigSourceSpecifier: &core.ConfigSource_Ads{
			Ads: &core.AggregatedConfigSource{},
		},
	}
}

func makeTypedExtensionProtocolOptions() map[string]*anypb.Any {
	httpProtocolOptions, err := anypb.New(&ext_http.HttpProtocolOptions{
		UpstreamProtocolOptions: &ext_http.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &ext_http.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &ext_http.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
					Http2ProtocolOptions: &core.Http2ProtocolOptions{},
				},
			},
		},
	})
	if httpProtocolOptions == nil && err != nil {
		panic(err)
	}

	return map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": httpProtocolOptions,
	}
}
