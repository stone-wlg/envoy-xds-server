package utils

type XDSServerConfig struct {
	Server struct {
		Id                      string `yaml:"id"`
		Port                    uint32 `yaml:"port"`
		RefreshInterval         uint64 `yaml:"refresh_interval"`
		SdsConfigClusterName    string `yaml:"sds_config_cluster_name"`
		TlsRootCaDefaultName    string `yaml:"tls_root_ca_default_name"`
		TlsPrivateCaDefaultName string `yaml:"tls_private_ca_default_name"`
	}

	Party struct {
		Id string `yaml:"id"`
	}

	Mysql struct {
		Host       string `yaml:"host"`
		Port       uint32 `yaml:"port"`
		User       string `yaml:"user"`
		Password   string `yaml:"password"`
		Database   string `yaml:"database"`
		PeerSQL    string `yaml:"peer_sql"`
		ServiceSQL string `yaml:"service_sql"`
	}
}

type Peer struct {
	PartyId       string
	Type          string
	Host          string
	Port          uint32
	tlsRootCa     string
	tlsPrivateCa  string
	tlsPrivateKey string
}

type Service struct {
	PartyId string
	Type    string
	Host    string
	Port    uint32
}
