package signing

import (
	"crypto/ecdsa"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/stretchr/testify/assert"
)

// go test -bench=. -run=none -cpu=1 -benchtime=10s .

func BenchmarkLindellSigningSerial(b *testing.B) {
	runSigningSerial(b) // 2/3
}

func BenchmarkLindellSigningParallel(b *testing.B) {
	runSigningParallel(b) // 2/3
}

func runSigningSerial(b *testing.B) {
	signKeys, signPIDs, err := LoadKeygenTestFixturesRandomSet(2, 3)
	assert.NoError(b, err, "should load keygen fixtures")
	assert.Equal(b, 2, len(signKeys))
	assert.Equal(b, 2, len(signPIDs))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runSigningOnce(b, signPIDs, signKeys)
	}
}

func runSigningParallel(b *testing.B) {
	signKeys, signPIDs, err := LoadKeygenTestFixturesRandomSet(2, 3)
	assert.NoError(b, err, "should load keygen fixtures")
	assert.Equal(b, 2, len(signKeys))
	assert.Equal(b, 2, len(signPIDs))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			runSigningOnce(b, signPIDs, signKeys)
		}
	})
}

func runSigningOnce(b *testing.B, signPIDs tss.SortedPartyIDs, signKeys []keygen.LocalPartySaveData) {
	// use a shuffled selection of the list of signingParties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	signingParties := make([]tss.Party, len(signPIDs))

	signingErrCh := make(chan *tss.Error, len(signPIDs))
	signingOutCh := make(chan tss.Message, len(signPIDs))
	signingEndCh := make(chan common.SignatureData, len(signPIDs))

	var wgPrepare sync.WaitGroup
	isServer := false
	// init the signingParties
	for i := 0; i < len(signPIDs); i++ {
		i := i

		if i == 0 {
			isServer = true
		} else {
			isServer = false
		}
		params := NewLindellSignParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), 1, isServer)

		wgPrepare.Add(1)
		go func() {
			defer wgPrepare.Done()

			P := NewLocalParty(big.NewInt(42), params, signKeys[i], signingOutCh, signingEndCh).(*LocalParty)
			signingParties[i] = P
			go func(P tss.Party) {
				if err := P.Start(); err != nil {
					signingErrCh <- err
				}
			}(P)
		}()
	}
	wgPrepare.Wait()

	var ended int32
signing:
	for {
		select {
		case err := <-signingErrCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(b, err.Error())
			break signing

		case msg := <-signingOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signingParties {
					//if P.PartyID().Index == msg.GetFrom().Index {
					//	continue
					//}
					go SharedPartyUpdater(P, msg, signingErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					b.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go SharedPartyUpdater(signingParties[dest[0].Index], msg, signingErrCh)
			}

		case msg := <-signingEndCh:
			atomic.AddInt32(&ended, 1)

			if msg.GetR() != nil {
				// BEGIN ECDSA verify
				pkX, pkY := signKeys[0].ECDSAPub.X(), signKeys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}

				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), big.NewInt(0).SetBytes(msg.GetR()), big.NewInt(0).SetBytes(msg.GetS()))
				assert.True(b, ok, "ecdsa verify must pass")
				// END ECDSA verify
			}

			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}
}
