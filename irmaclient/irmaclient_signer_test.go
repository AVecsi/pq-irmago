package irmaclient

import (
	"testing"

	"github.com/AVecsi/pq-gabi/signed"
	"github.com/AVecsi/pq-irmago/internal/test"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

func TestSignerJWT(t *testing.T) {
	signer := test.NewSigner(t)

	jwtt, err := SignerCreateJWT(signer, "keyname", jwt.MapClaims{"foo": "bar"})
	require.NoError(t, err)

	token, err := jwt.Parse(jwtt, func(*jwt.Token) (interface{}, error) {
		pk, err := signer.PublicKey("keyname")
		if err != nil {
			return nil, err
		}
		return signed.UnmarshalPublicKey(pk)
	})
	require.NoError(t, err)

	require.IsType(t, token.Claims, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)
	require.Contains(t, claims, "foo")
	require.Equal(t, claims["foo"], "bar")
}
