// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"go-rust/lindell/ffi"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	if !round.isServer {
		round.end <- common.SignatureData{}

		return nil
	}

	r2msg := round.temp.signRound2Messages[round.getOtherPartyId()].Content().(*SignRound2Message)
	var msg2 ffi.Round2Result
	if err := json.Unmarshal(r2msg.Rst, &msg2); err != nil {
		return round.WrapError(err)
	}

	partialSign := new(big.Int)
	partialSign.SetString(msg2.PartialSig.C3, 10)
	plain, err := round.key.PaillierSK.Decrypt(partialSign)
	if err != nil {
		return round.WrapError(err)
	}

	input3 := ffi.Round3Input{
		PlainSig: plain.String(),
		R1Rst:    *round.temp.round1Rst,
		R2Rst:    msg2,
	}

	rst3 := ffi.Round3(input3)

	sumS := new(big.Int)
	sumS.SetString(rst3.Sig.S, 10)

	Rx := new(big.Int)
	Rx.SetString(rst3.Sig.R, 10)

	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if Rx.Cmp(round.Params().EC().Params().N) > 0 {
		recid = 2
	}
	// TODO: should update it here
	//if round.temp.ry.Bit(0) != 0 {
	//	recid |= 1
	//}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(round.Params().EC().Params().N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(round.Params().EC().Params().N, sumS)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := round.Params().EC().Params().BitSize / 8
	round.data.R = padToLengthBytesInPlace(Rx.Bytes(), bitSizeInBytes)
	round.data.S = padToLengthBytesInPlace(sumS.Bytes(), bitSizeInBytes)
	round.data.Signature = append(round.data.R, round.data.S...)
	round.data.SignatureRecovery = []byte{byte(recid)}
	round.data.M = round.temp.m.Bytes()

	pk := ecdsa.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.ECDSAPub.X(),
		Y:     round.key.ECDSAPub.Y(),
	}
	ok := ecdsa.Verify(&pk, round.temp.m.Bytes(), Rx, sumS)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}

	round.end <- *round.data

	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round3) NextRound() tss.Round {
	return nil // finished!
}

func padToLengthBytesInPlace(src []byte, length int) []byte {
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src
}
