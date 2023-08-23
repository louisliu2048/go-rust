// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*SignRound2Message)(nil),
	}
)

// ----- //

func NewSignRound1Message(
	from *tss.PartyID,
	N, Share *big.Int,
	firstMsg []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From: from,
		//To:          []*tss.PartyID{to},
		IsBroadcast: true,
	}
	nBz := N.Bytes()
	sBz := Share.Bytes()
	content := &SignRound1Message{
		N:        nBz,
		Share:    sBz,
		FirstMsg: firstMsg,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetN()) && common.NonEmptyBytes(m.GetShare()) && common.NonEmptyBytes(m.GetFirstMsg())
}

func (m *SignRound1Message) UnmarshalN() *big.Int {
	return new(big.Int).SetBytes(m.GetN())
}

func (m *SignRound1Message) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.GetShare())
}

// ----- //

func NewSignRound2Message(
	from *tss.PartyID,
	rst2 []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound2Message{
		Rst: rst2,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.Rst)
}

// ----- //
