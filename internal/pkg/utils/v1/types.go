package utils

type XDSServerConfig struct {
	Server struct {
		Id                   string `yaml:"id"`
		Port                 uint32 `yaml:"port"`
		RefreshInterval      uint64 `yaml:"refresh_interval"`
		TlsCert              string `yaml:"tls_cert"`
		TlsValidationContext string `yaml:"tls_validation_context"`
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
	PartyId string
	Type    string
	Host    string
	Port    uint32
}

type Service struct {
	PartyId string
	Type    string
	Host    string
	Port    uint32
}
