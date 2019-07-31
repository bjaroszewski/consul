package connect

import (
	"github.com/hashicorp/consul/agent/structs"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSpiffeIDExternalServiceURI(t *testing.T) {
	svc := SpiffeIDExternalService{
		Host: "trust.domain",
		Path: "path",
	}
	assert.Equal(t, "spiffe://trust.domain/path", svc.URI().String())
}

func TestSpiffeIDExternalServiceAuthorize(t *testing.T) {
	ns := structs.IntentionDefaultNamespace
	cases := []struct {
		Name  string
		URI   *SpiffeIDExternalService
		Ixn   *structs.Intention
		Auth  bool
		Match bool
	}{
		{
			"consul intention",
			&SpiffeIDExternalService{
				Host: "host",
				Path: "path",
			},
			&structs.Intention{
				SourceNS:   ns,
				SourceType: structs.IntentionSourceConsul,
				SourceName: "foo",
			},
			false,
			false,
		},
		{
			"trust domain intention, domain matches, deny",
			&SpiffeIDExternalService{
				Host: "host",
				Path: "path",
			},
			&structs.Intention{
				SourceNS:   ns,
				SourceType: structs.IntentionSourceExternalTrustDomain,
				SourceName: "spiffe://host",
				Action:     structs.IntentionActionDeny,
			},
			false,
			true,
		},
		{
			"trust domain intention, domain matches, allow",
			&SpiffeIDExternalService{
				Host: "host",
				Path: "path",
			},
			&structs.Intention{
				SourceNS:   ns,
				SourceType: structs.IntentionSourceExternalTrustDomain,
				SourceName: "spiffe://host",
				Action:     structs.IntentionActionAllow,
			},
			true,
			true,
		},
		{
			"trust domain intention, domain doesn't match",
			&SpiffeIDExternalService{
				Host: "host",
				Path: "path",
			},
			&structs.Intention{
				SourceNS:   ns,
				SourceType: structs.IntentionSourceExternalTrustDomain,
				SourceName: "spiffe://other-host",
				Action:     structs.IntentionActionAllow,
			},
			false,
			false,
		},
		{
			"uri intention, path matches, deny",
			&SpiffeIDExternalService{
				Host: "host",
				Path: "path",
			},
			&structs.Intention{
				SourceNS:   ns,
				SourceType: structs.IntentionSourceExternalURI,
				SourceName: "spiffe://host/path",
				Action:     structs.IntentionActionDeny,
			},
			false,
			true,
		},
		{
			"uri intention, path matches, allow",
			&SpiffeIDExternalService{
				Host: "host",
				Path: "path",
			},
			&structs.Intention{
				SourceNS:   ns,
				SourceType: structs.IntentionSourceExternalURI,
				SourceName: "spiffe://host/path",
				Action:     structs.IntentionActionAllow,
			},
			true,
			true,
		},
		{
			"uri intention, path doesn't match",
			&SpiffeIDExternalService{
				Host: "host",
				Path: "different-path",
			},
			&structs.Intention{
				SourceNS:   ns,
				SourceType: structs.IntentionSourceExternalURI,
				SourceName: "spiffe://host/path",
				Action:     structs.IntentionActionDeny,
			},
			false,
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			auth, match := tc.URI.Authorize(tc.Ixn)
			assert.Equal(t, tc.Auth, auth)
			assert.Equal(t, tc.Match, match)
		})
	}
}
