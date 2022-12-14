// Copyright 2019 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package utils

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

const (
	tlsName = "server_cert"

	rootName = "validation_context"

	privateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBhxmxueLxxmDkhVE7umMhUIUTSNaX34cMGUFbj73Mu0oAoGCCqGSM49
AwEHoUQDQgAE/Z1XoAVtc08mvtPgJioXzPji0nCusOdNXj7f/VTs+CZ6KiNy8Ja6
MbhTOmF/7rVtQT2JJV6Nig+ACEZdFBixTw==
-----END EC PRIVATE KEY-----`

	privateChain = `-----BEGIN CERTIFICATE-----
MIID3zCCAsegAwIBAgIUZWT/fTz7kny/z1T8toDgMyROVcQwDQYJKoZIhvcNAQEL
BQAwYDELMAkGA1UEBhMCQ04xETAPBgNVBAgTCFNoYW5naGFpMREwDwYDVQQHEwhT
aGFuZ2hhaTENMAsGA1UEChMEQkFOSzENMAsGA1UECxMEQkFOSzENMAsGA1UEAxME
QkFOSzAgFw0yMjA2MjIxMzA3MDBaGA8yMTIyMDUyOTEzMDcwMFowYDELMAkGA1UE
BhMCQ04xETAPBgNVBAgTCFNoYW5naGFpMREwDwYDVQQHEwhTaGFuZ2hhaTENMAsG
A1UEChMERkVEWDENMAsGA1UECxMERkVEWDENMAsGA1UEAxMERkVEWDBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABP2dV6AFbXNPJr7T4CYqF8z44tJwrrDnTV4+3/1U
7PgmeiojcvCWujG4Uzphf+61bUE9iSVejYoPgAhGXRQYsU+jggFYMIIBVDAOBgNV
HQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud
EwEB/wQCMAAwHQYDVR0OBBYEFNC6dCxk+pL8KvRrxDYw45XxAhhdMB8GA1UdIwQY
MBaAFGee4+9hez7qeOW2H8+hAWaOwBrLMIHUBgNVHREEgcwwgcmCCWxvY2FsaG9z
dIIUKi5wcm94eS5rdWJlZmF0ZS5uZXSCEiouc2xiLmt1YmVmYXRlLm5ldIIWKi5i
aXouc2xiLmt1YmVmYXRlLm5ldIIWKi5kbXouc2xiLmt1YmVmYXRlLm5ldIIWKi5n
YXRld2F5Lmt1YmVmYXRlLm5ldIIXKi5yb2xsc2l0ZS5rdWJlZmF0ZS5uZXSCFSou
cHVsc2FyLmt1YmVmYXRlLm5ldIIUKi5zcGFyay5rdWJlZmF0ZS5uZXSHBH8AAAEw
DQYJKoZIhvcNAQELBQADggEBAEmCQ6T9k1JinGoKpc3nKckfNEeLkfWBWOJX+rnK
kK7aMiwxrWP3hwYDEF0tmOW7dR7qvnptfiODNmfwGizRz/4M0sKMh96JgpXcCZIo
x7/WUCqs0asbM/kRcvA9q2rKoJ+mxEge8gTRoYoe1uO7eKtrKsowBz2lhNZCuzWw
S51iO1kX77UWEzpDpm/Z95ujSTxltIOp97elhetPebvWXa8fmB0eEcDZRWzaA9fF
5Dwaeyqws0ryqE1GapkDxyhkOCLZ7wc6T7QJd4y99Ed5c4wFYZaJFuJ5y2Z06y9o
Iwp8M2W2xljujax+3aZuc7wDAcqmOQPgUBBUEDlTjMGgFeU=
-----END CERTIFICATE-----`

	rootCert = `-----BEGIN CERTIFICATE-----
MIID3TCCAsWgAwIBAgIUATn/evrhB1h15bx2cWv3Ah1t+y4wDQYJKoZIhvcNAQEL
BQAwZjELMAkGA1UEBhMCQ04xETAPBgNVBAgTCFNoYW5naGFpMREwDwYDVQQHEwhT
aGFuZ2hhaTEPMA0GA1UEChMGWkVUWVVOMQ8wDQYDVQQLEwZaRVRZVU4xDzANBgNV
BAMTBlpFVFlVTjAgFw0yMjA2MjIxMzA3MDBaGA8yMTIyMDUyOTEzMDcwMFowYDEL
MAkGA1UEBhMCQ04xETAPBgNVBAgTCFNoYW5naGFpMREwDwYDVQQHEwhTaGFuZ2hh
aTENMAsGA1UEChMEQkFOSzENMAsGA1UECxMEQkFOSzENMAsGA1UEAxMEQkFOSzCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM4fRX3VF2n4CElld85BNJ7b
68w4uRE2ITfxPk6qwbFerfihI8eBTEBfC1l6Lv2rxSZS8Qi46uV2/gUoEXOg0zcN
Ypb1+xvUZjUMoOUMn/4/BHSIcfLfbMtirhPk2j+xn1jfZNUMLnzPbWeZYcDumSo/
O71xbxRAFY11zEfG1xrpZ4Z9Ov837ApN1IbJdMDao3QvJQYg6ESnnDwIifGpEWKo
4g/diFkDPrRkppw13hR2TiR9B+58V/Zjp0TKR3hENkWAPyADymLDKtZP7GYMjpkf
ZOg9DbdJkx9ohn8roNMGAVFj5EiBzfupDqoxwq0WgKMy0zcoFk9gE3FlTlrfpS0C
AwEAAaOBhjCBgzAOBgNVHQ8BAf8EBAMCAaYwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFGee4+9hez7q
eOW2H8+hAWaOwBrLMB8GA1UdIwQYMBaAFIUqpLHhd+h61VWtatcnylQKLuCrMA0G
CSqGSIb3DQEBCwUAA4IBAQDQHa8xTtcqWBibCh7pXL+Sae1g8sGOtiEYUXO3fx9H
nxSykruGaXlW2BBov/2hM7lku88jDFnsYs4LHQdKnjR+NkaJhThpagrDOayrb2JT
a2dbBmLsEvv2d4NPq40atPhwbe7c40w8lAMjoRU8RDTi3sSXppq2OPYG8QBS4Epo
PXOJm8JIpWMBoptwVUIw91Z2TC5BJMi/5rj5Z5Yn4SsZQD4UF5x1+vKM3gjm+VoJ
28nLgUbFKII29eB+XWrDcCQJrhVlIjQulmk84WKc4s6v9DYgKKfM4lgzpbCoC+9K
fykWizTbSIDkmPzJAj4v2WRWUYW00Y02nTkq9D39kLtE
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDnjCCAoagAwIBAgIUBkokcDi1TdfKQ+tQBSoGz4LnRdowDQYJKoZIhvcNAQEL
BQAwZjELMAkGA1UEBhMCQ04xETAPBgNVBAgTCFNoYW5naGFpMREwDwYDVQQHEwhT
aGFuZ2hhaTEPMA0GA1UEChMGWkVUWVVOMQ8wDQYDVQQLEwZaRVRZVU4xDzANBgNV
BAMTBlpFVFlVTjAgFw0yMjA2MjIxMzA3MDBaGA8yMTIyMDUyOTEzMDcwMFowZjEL
MAkGA1UEBhMCQ04xETAPBgNVBAgTCFNoYW5naGFpMREwDwYDVQQHEwhTaGFuZ2hh
aTEPMA0GA1UEChMGWkVUWVVOMQ8wDQYDVQQLEwZaRVRZVU4xDzANBgNVBAMTBlpF
VFlVTjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEN4aQyTG7wYQCj
3e1d6kd5sEi2y9wttdSoTPUeC1fN0ZJvKwhK0JJ2cy4bDCPoLFLEsupTntiHbQNO
3gAeN954qNuxHIOUi8czRlXOtOBV26AhO/O93moJIdXzGnBfUZRg3iXppNMW7t17
o2LytADAdwuspWLOOsQV5drXXzPnm/DVq3JSPUBtNojCCuLOdJanLOlYybZVi4X0
HAv1yln0SBHBWFw5gBF39tESLSH4mCmqGcxPw6Y42f/O20CIJy5YXzQcN0q8Hfuu
uOMryJR30GB+6SxJ90V4zlWHrWo4RMO8GSMvoug8iDLS3OeCr4weL+CgOMa7Jn+6
XuzQbpcCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFIUqpLHhd+h61VWtatcnylQKLuCrMA0GCSqGSIb3DQEBCwUAA4IB
AQATaJcaSywFwcmzVeITAV+21rw/iNUF8ZAzICqcvX1TlLqcZWWDJismjsGG+gI1
+pEr+4qjhhlWdJ95eJgubqBoic3lI2QNNl0tYtTq6KBazvQrqSe2AqEKCCrVg86/
E+2SLcJQKDvRnZwTpsgvrhMx9uMniaypWgZOH2AfNNGv2VTEnNQpqDmkwj0ReheL
BmI0BrJm23jo/BvaZ2RhzwIYm13Rm2icDk6Dm0jkT/Jderlod4JdK+SlhwCcC37F
utqsqiixnQrDU/Iax1TD0aop/v+QH1lLDIy3FEHj421GZ2saDZ+N691pOuTHjcxQ
4gJvDXECU9GUPu6lWZXjmqFi
-----END CERTIFICATE-----`
)

// MakeSecrets generates an SDS secret
func MakeSecrets(tlsName, rootName string) []*auth.Secret {
	return []*auth.Secret{
		{
			Name: tlsName,
			Type: &auth.Secret_TlsCertificate{
				TlsCertificate: &auth.TlsCertificate{
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(privateKey)},
						// Specifier: &core.DataSource_InlineString{InlineString: privateKey},
					},
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(privateChain)},
						// Specifier: &core.DataSource_InlineString{InlineString: privateChain},
					},
				},
			},
		},
		{
			Name: rootName,
			Type: &auth.Secret_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(rootCert)},
						// Specifier: &core.DataSource_InlineString{InlineString: rootCert},
					},
				},
			},
		},
	}
}
