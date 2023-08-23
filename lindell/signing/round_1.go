// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/json"
	"errors"
	"fmt"

	"go-rust/lindell/ffi"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

func newRound1(params *LindellSignParameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	// Spec requires calculate H(M) here,
	// but considered different blockchain use different hash function we accept the converted big.Int
	// if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
	if round.temp.m.Cmp(round.Params().EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	if !round.isServer {
		return nil
	}

	encryptedShare, _, err := round.key.PaillierSK.EncryptAndReturnRandomness(round.temp.secretShare)
	if err != nil {
		return round.WrapError(err)
	}

	r1Rst := ffi.Round1()
	round.temp.round1Rst = &r1Rst

	firstMsg, err := json.Marshal(r1Rst.EphPartyOneFirstMessage)
	if err != nil {
		return round.WrapError(err)
	}

	//for _, Pj := range round.Parties().IDs() {
	//	if j == i {
	//		continue
	//	}
	//
	//	r1msg := NewSignRound1Message(Pj, round.PartyID(), round.key.PaillierSK.PublicKey.N, encryptedShare, firstMsg)
	//	round.out <- r1msg
	//}

	r1msg := NewSignRound1Message(round.PartyID(), round.key.PaillierSK.PublicKey.N, encryptedShare, firstMsg)
	round.out <- r1msg

	// server auto advanced to next round
	//round.NextRound().Start()

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	if round.isServer {
		round.setOK()
		return true, nil
	}

	for j, msg := range round.temp.signRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.temp.keyDerivationDelta != nil {
		// adding the key derivation delta to the xi's
		// Suppose x has shamir shares x_0,     x_1,     ..., x_n
		// So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
		mod := common.ModInt(round.Params().EC().Params().N)
		xi = mod.Add(round.temp.keyDerivationDelta, xi)
		round.key.Xi = xi
	}

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks)

	round.temp.secretShare = wi
	round.temp.publicShare = round.key.ECDSAPub.X() // todo: 设置的不对，需要重新设置
	return nil
}
