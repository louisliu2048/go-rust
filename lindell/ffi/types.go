package ffi

import "math/big"

type Point struct {
	Curve string `json:"curve"`
	Point []uint `json:"point"`
}

type Scalar struct {
	Curve  string `json:"curve"`
	Scalar []uint `json:"scalar"`
}

type EcKeyPair struct {
	PublicShare Point  `json:"public_share"`
	SecretShare Scalar `json:"secret_share"`
}

type DecryptionKey struct {
	P string `json:"p"` // first prime
	Q string `json:"q"` // second prime
}

type Party1Private struct {
	X1             Scalar        `json:"x1"`
	PaillierPriv   DecryptionKey `json:"paillier_priv"`
	CKeyRandomness string        `json:"c_key_randomness"`
}

type ECDDHProof struct {
	A1 Point  `json:"a1"`
	A2 Point  `json:"a2"`
	Z  Scalar `json:"z"`
}

type EphKeyGenFirstMsg struct {
	DLogProof   ECDDHProof `json:"d_log_proof"`
	PublicShare Point      `json:"public_share"`
	C           Point      `json:"c"`
}

type EphEcKeyPair struct {
	PublicShare Point  `json:"public_share"`
	SecretShare Scalar `json:"secret_share"`
}

type Round1Result struct {
	EphEcKeyPairParty1 EphEcKeyPair `json:"eph_ec_key_pair_party1"`

	// msg to ->party2
	EphPartyOneFirstMessage EphKeyGenFirstMsg `json:"eph_party_one_first_message"`
}

type Round2Input struct {
	PaillierN      string `json:"paillier_n"`
	EncryptedShare string `json:"encrypted_share"`

	// msg to sign
	Message string `json:"message"`

	EcKeyPairParty2 EphEcKeyPair `json:"ec_key_pair_party2"`

	// msg from <- party1
	EphPartyOneFirstMessage EphKeyGenFirstMsg `json:"eph_party_one_first_message"`
}

type EphKeyGenSecondMsg struct {
	CommWitness EphCommWitness `json:"comm_witness"`
}

type EphCommWitness struct {
	PkCommitmentBlindFactor string     `json:"pk_commitment_blind_factor"`
	ZkPokBlindFactor        string     `json:"zk_pok_blind_factor"`
	PublicShare             Point      `json:"public_share"`
	DLogProof               ECDDHProof `json:"d_log_proof"`
	C                       Point      `json:"c"` //c = secret_share * base_point2
}

type PartialSig struct {
	C3 string `json:"c3"`
}

type PartyTwoEphKeyGenFirstMsg struct {
	PkCommitment    string `json:"pk_commitment"`
	ZkPokCommitment string `json:"zk_pok_commitment"`
}

type Round2Result struct {
	EphPartyTwoFirstMessage  PartyTwoEphKeyGenFirstMsg `json:"eph_party_two_first_message"`
	EphPartyTwoSecondMessage EphKeyGenSecondMsg        `json:"eph_party_two_second_message"`
	PartialSig               PartialSig                `json:"partial_sig"`
}

type Round3Input struct {
	PlainSig string       `json:"plain_sign"`
	R1Rst    Round1Result `json:"r1_rst"`
	R2Rst    Round2Result `json:"r2_rst"`
}

type Signature struct {
	S string `json:"s"`
	R string `json:"r"`
}

type Round3Result struct {
	Sig Signature `json:"signature"`
}

func Bytes2Uint(data []byte) []uint {
	rst := make([]uint, len(data))
	for idx, b := range data {
		rst[idx] = uint(b)
	}

	return rst
}

func Uint2Byte(data []uint) []byte {
	rst := make([]byte, len(data))
	for idx, b := range data {
		rst[idx] = byte(b)
	}

	return rst
}

func Str2BigInt(val string) *big.Int {
	rst := new(big.Int)
	rst.SetString(val, 10)
	return rst
}
