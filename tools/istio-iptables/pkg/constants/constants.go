// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package constants

// Constants used in iptables commands
const (
	MANGLE = "mangle"
	NAT    = "nat"

	TCP = "tcp"

	TPROXY          = "TPROXY"
	PREROUTING      = "PREROUTING"
	RETURN          = "RETURN"
	ACCEPT          = "ACCEPT"
	REJECT          = "REJECT"
	INPUT           = "INPUT"
	OUTPUT          = "OUTPUT"
	REDIRECT        = "REDIRECT"
	MARK            = "MARK"
	ISTIOOUTPUT     = "ISTIO_OUTPUT"
	ISTIOINBOUND    = "ISTIO_INBOUND"
	ISTIODIVERT     = "ISTIO_DIVERT"
	ISTIOTPROXY     = "ISTIO_TPROXY"
	ISTIOREDIRECT   = "ISTIO_REDIRECT"
	ISTIOINREDIRECT = "ISTIO_IN_REDIRECT"
)

// Constants used in cobra/viper CLI
const (
	InboundInterceptionMode   = "istio-inbound-interception-mode"
	InboundTProxyMark         = "istio-inbound-tproxy-mark"
	InboundTProxyRouteTable   = "istio-inbound-tproxy-route-table"
	InboundPorts              = "istio-inbound-ports"
	LocalExcludePorts         = "istio-local-exclude-ports"
	ServiceCidr               = "istio-service-cidr"
	ServiceExcludeCidr        = "istio-service-exclude-cidr"
	LocalOutboundPortsExclude = "istio-local-outbound-ports-exclude"
	EnvoyPort                 = "envoy-port"
	InboundCapturePort        = "inbound-capture-port"
	ProxyUID                  = "proxy-uid"
	ProxyGID                  = "proxy-gid"
	KubeVirtInterfaces        = "kube-virt-interfaces"
	DryRun                    = "dry-run"
	Clean                     = "clean"
)
