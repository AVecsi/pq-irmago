package sessiontest

import (
	"testing"

	irma "github.com/AVecsi/pq-irmago"
	"github.com/AVecsi/pq-irmago/internal/test"
	"github.com/AVecsi/pq-irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

// TestPQIssuanceAndDisclosure tests the full issuance + disclosure flow through the
// real IRMA server and client stack, exactly as the mobile app would.
func TestPQIssuanceAndDisclosure(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	// Start fresh — remove any pre-existing credentials from legacy storage
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	// Step 1: Issue a credential
	issuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		Attributes: map[string]string{
			"university":        "Radboud",
			"studentCardNumber": "31415927",
			"studentID":         "s1234567",
			"level":             "42",
		},
	}})

	result := doSession(t, issuanceRequest, client, nil, nil, nil, IrmaServerConfiguration)
	require.Nil(t, result.Err, "issuance session failed: %v", result.Err)
	require.Equal(t, irma.ServerStatusDone, result.Status)

	t.Log("✅ Issuance session completed")

	// Step 2: Disclose an attribute from the just-issued credential
	disclosureRequest := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
	)

	discResult := doSession(t, disclosureRequest, client, nil, nil, nil, IrmaServerConfiguration)
	require.Nil(t, discResult.Err, "disclosure session failed: %v", discResult.Err)
	require.Equal(t, irma.ProofStatusValid, discResult.ProofStatus)
	require.Len(t, discResult.Disclosed, 1)
	require.Equal(t, "s1234567", discResult.Disclosed[0][0].Value["en"])

	t.Log("✅ Disclosure session completed and verified")
}

// TestPQIssuanceAndMultiAttributeDisclosure tests disclosing multiple attributes
// from an issued credential.
func TestPQIssuanceAndMultiAttributeDisclosure(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	// Start fresh — remove any pre-existing credentials from legacy storage
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	// Issue credential
	issuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		Attributes: map[string]string{
			"university":        "Radboud",
			"studentCardNumber": "31415927",
			"studentID":         "s1234567",
			"level":             "42",
		},
	}})

	result := doSession(t, issuanceRequest, client, nil, nil, nil, IrmaServerConfiguration)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ServerStatusDone, result.Status)

	t.Log("✅ Issuance session completed")

	// Disclose multiple attributes
	disclosureRequest := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"),
	)

	discResult := doSession(t, disclosureRequest, client, nil, nil, nil, IrmaServerConfiguration)
	require.Nil(t, discResult.Err)
	require.Equal(t, irma.ProofStatusValid, discResult.ProofStatus)
	require.Len(t, discResult.Disclosed, 2) // metadata always disclosed

	t.Log("✅ Multi-attribute disclosure session completed and verified")
}

// TestPQIssuanceStoredAndDisclosure tests that after closing and reopening the client
// (simulating app restart), the credential is still there and can be disclosed.
func TestPQIssuanceStoredAndDisclosure(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	// Start fresh — remove any pre-existing credentials from legacy storage
	require.NoError(t, client.RemoveStorage())
	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})

	// Issue credential
	issuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		Attributes: map[string]string{
			"university":        "Radboud",
			"studentCardNumber": "31415927",
			"studentID":         "s1234567",
			"level":             "42",
		},
	}})

	result := doSession(t, issuanceRequest, client, nil, nil, nil, IrmaServerConfiguration)
	require.Nil(t, result.Err)

	t.Log("✅ Issuance session completed")

	// Simulate app restart: close and reopen storage
	require.NoError(t, client.Close())
	client, _ = parseExistingStorage(t, handler.storage)

	t.Log("✅ Client storage reloaded (simulating app restart)")

	// Disclose after restart
	disclosureRequest := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
	)

	discResult := doSession(t, disclosureRequest, client, nil, nil, nil, IrmaServerConfiguration)
	require.Nil(t, discResult.Err)
	t.Log(discResult.Err)
	require.Equal(t, irma.ProofStatusValid, discResult.ProofStatus)
	require.Equal(t, "s1234567", discResult.Disclosed[0][0].Value["en"])

	t.Log("✅ Disclosure after restart completed and verified")
}
