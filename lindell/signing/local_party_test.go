// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func SharedPartyUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	// do not send a message from this party back to itself
	//if party.PartyID() == msg.GetFrom() {
	//	return
	//}
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")
	threshold := 1
	//participants := 3

	// PHASE: load keygen fixtures
	keys, signPIDs, err := LoadKeygenTestFixtures(threshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, threshold+1, len(keys))
	assert.Equal(t, threshold+1, len(signPIDs))

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	isServer := false
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		if i == 0 {
			isServer = true
		} else {
			isServer = false
		}
		params := NewLindellSignParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold, isServer)

		P := NewLocalParty(big.NewInt(42), params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					//if P.PartyID().Index == msg.GetFrom().Index {
					//	continue
					//}
					go SharedPartyUpdater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go SharedPartyUpdater(parties[dest[0].Index], msg, errCh)
			}

		case msg := <-endCh:
			atomic.AddInt32(&ended, 1)
			t.Logf("Done. Received signature data from %d participants", ended)

			if msg.GetR() != nil {
				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}

				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), big.NewInt(0).SetBytes(msg.GetR()), big.NewInt(0).SetBytes(msg.GetS()))
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify
			}

			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}
}
