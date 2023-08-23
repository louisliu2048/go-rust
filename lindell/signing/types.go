package signing

import (
	"crypto/elliptic"

	"github.com/bnb-chain/tss-lib/tss"
)

type LindellSignParameters struct {
	*tss.Parameters
	isServer bool
}

func NewLindellSignParameters(ec elliptic.Curve, ctx *tss.PeerContext, partyID *tss.PartyID, partyCount, threshold int,
	isServer bool) *LindellSignParameters {
	params := tss.NewParameters(ec, ctx, partyID, partyCount, threshold)
	return &LindellSignParameters{
		Parameters: params,
		isServer:   isServer,
	}
}
