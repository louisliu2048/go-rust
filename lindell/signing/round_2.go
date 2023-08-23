// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/json"
	"errors"
	"math/big"

	"go-rust/lindell/ffi"

	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	if round.isServer {
		return nil
	}

	r1msg := round.temp.signRound1Messages[round.getOtherPartyId()].Content().(*SignRound1Message)
	var msg1 ffi.EphKeyGenFirstMsg
	err := json.Unmarshal(r1msg.FirstMsg, &msg1)
	if err != nil {
		return round.WrapError(err)
	}

	pubShare := make([]byte, 1, 33)
	pubShare[0] = 3
	pubShare = append(pubShare, round.temp.publicShare.Bytes()...)

	input2 := ffi.Round2Input{
		PaillierN:      new(big.Int).SetBytes(r1msg.N).String(),
		EncryptedShare: new(big.Int).SetBytes(r1msg.Share).String(),
		EcKeyPairParty2: ffi.EphEcKeyPair{
			PublicShare: ffi.Point{
				Curve: "secp256k1",
				Point: ffi.Bytes2Uint(pubShare),
			},
			SecretShare: ffi.Scalar{
				Curve:  "secp256k1",
				Scalar: ffi.Bytes2Uint(round.temp.secretShare.Bytes()),
			},
		},
		Message:                 round.temp.m.String(),
		EphPartyOneFirstMessage: msg1,
	}

	rst2 := ffi.Round2(input2)
	rstData, err := json.Marshal(rst2)
	if err != nil {
		return round.WrapError(err)
	}

	// create and send messages
	//for j, Pj := range round.Parties().IDs() {
	//	if j == i {
	//		continue
	//	}
	//	r2msg := NewSignRound2Message(Pj, round.PartyID(), rstData)
	//	round.out <- r2msg
	//}

	r2msg := NewSignRound2Message(round.PartyID(), rstData)
	round.out <- r2msg

	// client auto advanced to next round
	//round.NextRound().Start()

	return nil
}

func (round *round2) Update() (bool, *tss.Error) {
	if !round.isServer {
		round.setOK()
		return true, nil
	}

	for j, msg := range round.temp.signRound2Messages {
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

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}

func (round *round2) getOtherPartyId() int {
	i := round.PartyID().Index

	for j, _ := range round.Parties().IDs() {
		if j == i {
			continue
		}
		return j
	}

	return i
}
