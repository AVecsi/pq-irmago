package irmaclient

import (
	gabi "github.com/AVecsi/pq-gabi"
	irma "github.com/AVecsi/pq-irmago"
)

// credential represents an IRMA credential, whose zeroth attribute
// is always the secret key and the first attribute the metadata attribute.
type credential struct {
	*gabi.Credential
	*irma.MetadataAttribute
	attrs *irma.AttributeList
}

func newCredential(gabicred *gabi.Credential, attrs *irma.AttributeList, conf *irma.Configuration) (*credential, error) {
	meta := irma.MetadataFromInt(gabicred.Attributes[1].IntValue(), conf)
	cred := &credential{
		Credential:        gabicred,
		MetadataAttribute: meta,
	}

	if cred.CredentialType() == nil {
		// Unknown credtype, populate Pk field later
		return cred, nil
	}

	cred.attrs = attrs
	return cred, nil
}
