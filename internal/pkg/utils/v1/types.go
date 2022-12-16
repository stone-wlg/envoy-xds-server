package utils

type XDSServerConfig struct {
	Peer struct {
		Id              string `yaml:"id"`
		Name            string `yaml:"name"`
		Port            uint32 `yaml:"port"`
		RefreshInterval uint64 `yaml:"refresh_interval"`
	}

	Features []*struct {
		Index  string `yaml:"index"`
		Name   string `yaml:"name"`
		Module string `yaml:"module"`
		Mode   string `yaml:"mode"`
		Port   uint32 `yaml:"port"`
	}

	Secret struct {
		SdsConfigClusterName    string `yaml:"sds_config_cluster_name"`
		TlsRootCaDefaultName    string `yaml:"tls_root_ca_default_name"`
		TlsPrivateCaDefaultName string `yaml:"tls_private_ca_default_name"`
		DefaultRootCa           string `yaml:"default_root_ca"`
		DefaultPrivateCa        string `yaml:"default_private_ca"`
		DefaultPrivateKey       string `yaml:"default_private_key"`
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
	Id            string
	Mode          string
	Host          string
	Port          uint32
	tlsRootCa     string
	tlsPrivateCa  string
	tlsPrivateKey string
}

type Service struct {
	Id     string
	Mode   string
	Host   string
	Port   uint32
	PeerId string
}
