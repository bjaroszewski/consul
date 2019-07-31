package connect

import (
	"net/url"

	"github.com/hashicorp/consul/agent/structs"
)

// SpiffeIDExternalService represents a service with a generic SPIFFE ID that
// is external to Consul.
type SpiffeIDExternalService struct {
	Host string
	Path string
}

// URI returns the *url.URL for this SPIFFE ID.
func (id *SpiffeIDExternalService) URI() *url.URL {
	var result url.URL
	result.Scheme = "spiffe"
	result.Host = id.Host
	result.Path = id.Path
	return &result
}

// CertURI impl.
func (id *SpiffeIDExternalService) Authorize(ixn *structs.Intention) (bool, bool) {
	if ixn.SourceType == structs.IntentionSourceExternalTrustDomain &&
		ixn.SourceName == "spiffe://"+id.Host {
		return ixn.Action == structs.IntentionActionAllow, true
	} else if ixn.SourceType == structs.IntentionSourceExternalURI &&
		ixn.SourceName == id.URI().String() {
		return ixn.Action == structs.IntentionActionAllow, true
	}
	return false, false
}
