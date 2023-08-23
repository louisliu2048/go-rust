package lindell

import (
	"crypto/ecdsa"
	"encoding/json"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"go-rust/lindell/signing"
	"math/big"
	"testing"

	"go-rust/lindell/ffi"

	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/stretchr/testify/assert"
)

// go test -bench=. -run=none -cpu=1 -benchtime=10s .

func BenchmarkLindellSigningSerial(b *testing.B) {
	runSigningSerial(b) // 2/2
}

func BenchmarkLindellSigningParallel(b *testing.B) {
	runSigningParallel(b) // 2/2
}

func runSigningSerial(b *testing.B) {
	party1KeyStr := `{"x1":{"curve":"secp256k1","scalar":[18,145,53,92,155,177,161,193,151,116,192,33,113,184,47,23,76,102,5,110,75,79,154,76,77,9,28,149,22,235,214,209]},"paillier_priv":{"p":"137011065195882922300331368001124313983722327643321832355387496023829485899993048330000017579700347702398965702182351207641733095878161311153387201159340422359915255532041342700874486900841091388351490714037782113844110184190722438431436946754041452387471603524895220159558480675144819323831804616587549636411","q":"112787300175899987568204194294559966800216308794713588076591241431546999257357980322596241227313565675472577125532179773886338223615893842734094102260801848172811071446946449235647980815311732428704660910538769529774854227799108753801288525671836232275839107991168264533934073486258720450292271840905837755053"},"c_key_randomness":"72700639327511104965518183215788693417369684139372843655204273831077899050196979418250116449888337729314601081637387142524647477349366917575113493550047580642932173550950821754921369061449425094934792628192156624456476886854898636533282240253993802283810929414745024109725595874942824203071611125645239075164722057779961512009564778405973532672913311407995891025091185476921004862378022800977918272469643004259540878397000284510353880925131073595282423731088207150616088814003315811649626045390727319979557248704425194548209877025032762392807515163442988899619059048083923052903643887749570758410138238321095016990"}`
	input2Str := `{"paillier_n":"15453108137667850587026384497369588865052224775570073725993309326495366523991669206594399207496819200050463624967544836174921258210946815255126405995904187130079198265007890408276492485325130874361633623833170726648447821755086459130526921389779073845890531117209524092785802556441822851554867095637818673869236231078603663281248644223479862002646466553476539972565546380447956264804378369256642411505855507008568567051868798770287109216353835717570031675747781261606712855763686428159564736800030834961303392259612397748382955459413473582577117823704304895661889400916964043543607902849223273926561334516746628034783","encrypted_share":"224782462767766316063514392915806803306948787831544068973106627706499051452139613639860330722317327231801136772875818625329509582138471570913018611340987335851345926453409529027964142318152523480564343140794564136207674077934544806177748578103733236631142482097993345774944014318734171435579799308278354425452731363685470113467620065957585557703278552337226286241636304322746729479429377673503869788349324069441090748949647067805881135558245256898168503596644535903939834008019863670190068405477143199106354272993395238189346830967717369286699932465234794587745811912814260032513257800001260623967943711074315025288622738571057221532810544685576697488701226489425417565322245556930841349991943548120033411697854106657816395326286833470470590699754973034969769756191564341870048505805606350610158175890189343765725466567143323731777466985177176415400635104213585105711894882617325771852764384254004593570593972516665035267382121098352474159297496430199004169572901446142258301092845625962480565264991329540467223408195134516642080929962584028537381251245980851978631797054206885173854379823630768218449251738815245723084643538580652139558956320113455127612786581302487358347604942320954133124792668132363172076784375922534482460882429","ec_key_pair_party2":{"public_share":{"curve":"secp256k1","point":[2,238,123,166,171,233,61,177,230,244,73,80,218,189,232,247,6,118,49,191,3,114,46,145,0,143,236,252,236,234,27,178,99]},"secret_share":{"curve":"secp256k1","scalar":[143,203,149,110,22,138,19,21,48,112,240,197,233,13,97,186,27,140,87,111,83,127,48,89,166,106,107,253,143,59,193,0]}},"message":"1234","eph_party_one_first_message":{"d_log_proof":{"a1":{"curve":"secp256k1","point":[3,53,217,97,4,6,87,153,130,83,57,243,224,191,30,222,5,16,153,132,91,2,223,224,55,125,82,239,102,228,134,243,116]},"a2":{"curve":"secp256k1","point":[3,170,79,90,170,129,186,111,62,149,168,2,119,112,202,77,132,57,77,57,222,88,191,110,38,107,169,198,149,15,111,76,207]},"z":{"curve":"secp256k1","scalar":[40,221,85,146,35,105,174,65,212,190,15,242,67,170,131,60,122,183,233,248,142,173,137,64,121,49,244,255,107,87,62,202]}},"public_share":{"curve":"secp256k1","point":[3,211,151,28,250,107,5,240,68,143,198,212,167,167,61,170,37,17,14,1,101,127,185,42,239,198,86,100,57,109,247,174,179]},"c":{"curve":"secp256k1","point":[2,175,41,153,212,173,142,253,56,197,124,116,175,15,106,133,122,101,177,102,166,181,41,118,125,117,34,67,128,167,157,21,239]}}}`

	var party1Key ffi.Party1Private
	err := json.Unmarshal([]byte(party1KeyStr), &party1Key)
	assert.Nil(b, err)

	var input2 ffi.Round2Input
	err = json.Unmarshal([]byte(input2Str), &input2)
	assert.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runSigningOnce(b, party1Key, input2)
	}
}

func runSigningParallel(b *testing.B) {
	party1KeyStr := `{"x1":{"curve":"secp256k1","scalar":[18,145,53,92,155,177,161,193,151,116,192,33,113,184,47,23,76,102,5,110,75,79,154,76,77,9,28,149,22,235,214,209]},"paillier_priv":{"p":"137011065195882922300331368001124313983722327643321832355387496023829485899993048330000017579700347702398965702182351207641733095878161311153387201159340422359915255532041342700874486900841091388351490714037782113844110184190722438431436946754041452387471603524895220159558480675144819323831804616587549636411","q":"112787300175899987568204194294559966800216308794713588076591241431546999257357980322596241227313565675472577125532179773886338223615893842734094102260801848172811071446946449235647980815311732428704660910538769529774854227799108753801288525671836232275839107991168264533934073486258720450292271840905837755053"},"c_key_randomness":"72700639327511104965518183215788693417369684139372843655204273831077899050196979418250116449888337729314601081637387142524647477349366917575113493550047580642932173550950821754921369061449425094934792628192156624456476886854898636533282240253993802283810929414745024109725595874942824203071611125645239075164722057779961512009564778405973532672913311407995891025091185476921004862378022800977918272469643004259540878397000284510353880925131073595282423731088207150616088814003315811649626045390727319979557248704425194548209877025032762392807515163442988899619059048083923052903643887749570758410138238321095016990"}`
	input2Str := `{"paillier_n":"15453108137667850587026384497369588865052224775570073725993309326495366523991669206594399207496819200050463624967544836174921258210946815255126405995904187130079198265007890408276492485325130874361633623833170726648447821755086459130526921389779073845890531117209524092785802556441822851554867095637818673869236231078603663281248644223479862002646466553476539972565546380447956264804378369256642411505855507008568567051868798770287109216353835717570031675747781261606712855763686428159564736800030834961303392259612397748382955459413473582577117823704304895661889400916964043543607902849223273926561334516746628034783","encrypted_share":"224782462767766316063514392915806803306948787831544068973106627706499051452139613639860330722317327231801136772875818625329509582138471570913018611340987335851345926453409529027964142318152523480564343140794564136207674077934544806177748578103733236631142482097993345774944014318734171435579799308278354425452731363685470113467620065957585557703278552337226286241636304322746729479429377673503869788349324069441090748949647067805881135558245256898168503596644535903939834008019863670190068405477143199106354272993395238189346830967717369286699932465234794587745811912814260032513257800001260623967943711074315025288622738571057221532810544685576697488701226489425417565322245556930841349991943548120033411697854106657816395326286833470470590699754973034969769756191564341870048505805606350610158175890189343765725466567143323731777466985177176415400635104213585105711894882617325771852764384254004593570593972516665035267382121098352474159297496430199004169572901446142258301092845625962480565264991329540467223408195134516642080929962584028537381251245980851978631797054206885173854379823630768218449251738815245723084643538580652139558956320113455127612786581302487358347604942320954133124792668132363172076784375922534482460882429","ec_key_pair_party2":{"public_share":{"curve":"secp256k1","point":[2,238,123,166,171,233,61,177,230,244,73,80,218,189,232,247,6,118,49,191,3,114,46,145,0,143,236,252,236,234,27,178,99]},"secret_share":{"curve":"secp256k1","scalar":[143,203,149,110,22,138,19,21,48,112,240,197,233,13,97,186,27,140,87,111,83,127,48,89,166,106,107,253,143,59,193,0]}},"message":"1234","eph_party_one_first_message":{"d_log_proof":{"a1":{"curve":"secp256k1","point":[3,53,217,97,4,6,87,153,130,83,57,243,224,191,30,222,5,16,153,132,91,2,223,224,55,125,82,239,102,228,134,243,116]},"a2":{"curve":"secp256k1","point":[3,170,79,90,170,129,186,111,62,149,168,2,119,112,202,77,132,57,77,57,222,88,191,110,38,107,169,198,149,15,111,76,207]},"z":{"curve":"secp256k1","scalar":[40,221,85,146,35,105,174,65,212,190,15,242,67,170,131,60,122,183,233,248,142,173,137,64,121,49,244,255,107,87,62,202]}},"public_share":{"curve":"secp256k1","point":[3,211,151,28,250,107,5,240,68,143,198,212,167,167,61,170,37,17,14,1,101,127,185,42,239,198,86,100,57,109,247,174,179]},"c":{"curve":"secp256k1","point":[2,175,41,153,212,173,142,253,56,197,124,116,175,15,106,133,122,101,177,102,166,181,41,118,125,117,34,67,128,167,157,21,239]}}}`

	var party1Key ffi.Party1Private
	err := json.Unmarshal([]byte(party1KeyStr), &party1Key)
	assert.Nil(b, err)

	var input2 ffi.Round2Input
	err = json.Unmarshal([]byte(input2Str), &input2)
	assert.Nil(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			runSigningOnce(b, party1Key, input2)
		}
	})
}

func runSigningOnce(b *testing.B, party1Key ffi.Party1Private, input2 ffi.Round2Input) {
	rst1 := ffi.Round1()
	assert.NotNil(b, rst1)

	input2.EphPartyOneFirstMessage = rst1.EphPartyOneFirstMessage
	rst2 := ffi.Round2(input2)
	assert.NotNil(b, rst2)

	decryptionKey := GenerateKeyPair(ffi.Str2BigInt(party1Key.PaillierPriv.P), ffi.Str2BigInt(party1Key.PaillierPriv.Q))
	partialSig := ffi.Str2BigInt(rst2.PartialSig.C3)
	rst, err := decryptionKey.Decrypt(partialSig)
	assert.Nil(b, err)

	input3 := ffi.Round3Input{
		PlainSig: rst.String(),
		R1Rst:    rst1,
		R2Rst:    rst2,
	}

	rst3 := ffi.Round3(input3)
	assert.NotNil(b, rst3)
}

func TestLindell(t *testing.T) {
	input2Str := `{"paillier_n":"18504938864613671363746378788418213552070388456218034676818001038458184936646431828921011860546678286036016155455398076588976671874722065601730222937104351023661926293904642803511087718739374055575390090637318337319194804401455013040005192355310267335946784121967016870296379730428911442702128306558293975791075836277282737484270823875646695885534073876631989600236425658371602772931882783622967216340121143516884781017101955510170454269100198856644843158980462849001254186966464168581080750582893051700464173657968449976372835211510098033173769044327897445770307329512052146351218131782657510830138338818191326796721","encrypted_share":"77545905527166824592983718316235116049481986206479807150062250831067956747994431178268042795117780977118057018538624450483745898948512394562879704349609515354288811247683005430614922131334447250651130654873796648520303333492382147403956657228419612275605126253891635667404123279956815836365705520906307089042655734658260269066926061728694622572478379585983198408400601861716534075738939334177386727333582208159052428608603218958280149111183953696500922145275302343036071795657160630050555930722995350336192911771940584737189168715399881937098061455290346729566699038807930124466338014298183882132798630797002874821857118143712981002681682726948575397177213340135730559606190965271160157209083526066584370927916866035924965923871898736349269237528884881419917693582963030991377004065546646257155950759495578637012524485992592704171648638574807923288448266584345401914003286754919138519832207612018986779888667270697000448816645363404655574091018269440476452349420595012158600272505270402359913664897574780989219387871122123606267176672707882218061993724823438907164860690396934014441064793239961475162903146090098476713640521818393142038519344909071646174494854087247822865913067415791415369788828568239178591032356462772638536042953","ec_key_pair_party2":{"public_share":{"curve":"secp256k1","point":[3,205,59,147,32,242,32,125,228,6,61,94,169,199,115,164,73,195,136,6,205,108,117,130,133,26,149,129,191,184,118,174,118]},"secret_share":{"curve":"secp256k1","scalar":[33,28,106,193,29,249,241,247,170,54,78,192,238,160,98,139,33,154,181,16,182,50,93,22,201,136,213,151,169,91,70,120]}},"message":"1234","eph_party_one_first_message":{"d_log_proof":{"a1":{"curve":"secp256k1","point":[2,35,69,3,50,102,192,41,226,185,88,128,194,174,18,188,215,16,41,137,69,10,23,222,151,221,197,229,139,21,55,201,65]},"a2":{"curve":"secp256k1","point":[3,206,123,197,119,225,75,58,15,214,237,177,20,81,217,174,235,141,104,4,168,154,164,247,122,141,30,68,28,60,152,145,12]},"z":{"curve":"secp256k1","scalar":[4,233,43,72,102,84,253,248,222,46,111,48,171,135,251,164,175,232,72,32,201,10,126,92,142,147,56,212,125,60,222,129]}},"public_share":{"curve":"secp256k1","point":[3,213,85,120,188,234,31,218,134,17,179,18,152,183,148,47,18,180,153,37,140,251,28,122,182,174,239,59,10,195,251,214,190]},"c":{"curve":"secp256k1","point":[2,40,209,201,150,191,245,234,131,132,221,249,197,141,127,3,216,114,238,186,198,71,100,66,53,143,86,54,219,150,54,236,120]}}}`
	party1KeyStr := `{"x1":{"curve":"secp256k1","scalar":[136,135,85,124,0,218,4,228,18,47,14,64,114,100,72,161,87,130,184,251,185,204,35,211,5,78,4,33,132,218,134,18]},"paillier_priv":{"p":"143800107728886147995962278233960735716526997278458191507437524547814604392942640885627076734129026043843024606095619799821315655235150651603673295407161576092410797980409712640320907044691491044966541236992175680272258668515263330282341629152521935986903370617264806301925763457908450480420197217516842639531","q":"128685153000733482686286904235912801010952070937415349241976279137611645850966738635405906354594128102145354530167266436685551603900162320627033304638560547802756451842394957618997744641947482581553926674207807153245127456322738634176167545597063239550433573596493091793290565319617721270790815003853299977491"},"c_key_randomness":"3135610702459994063487917461002958047908990350213660263129962400036615534787348748884402855695991387809972522891310437915708431668696510768197861874285406998265978794723959181312996626882550666092361649933511728595173684531656166107717876409289693735051449425885614526114366966360655494169914478068829341701377162258904250072220783219143208149467352553396385392117856524430690582880625280926447198140971809007731907216976678656386715977112617485502441862693436709391718240339077372849203451627060755045394161023045006023828638548027450254564468565464657397078412055973067269879654515520001002337470157097488953130538"}`

	rst1 := ffi.Round1()
	assert.NotNil(t, rst1)

	var input2 ffi.Round2Input
	err := json.Unmarshal([]byte(input2Str), &input2)
	assert.Nil(t, err)

	input2.EphPartyOneFirstMessage = rst1.EphPartyOneFirstMessage
	rst2 := ffi.Round2(input2)
	assert.NotNil(t, rst2)

	var party1Key ffi.Party1Private
	err = json.Unmarshal([]byte(party1KeyStr), &party1Key)
	assert.Nil(t, err)

	decryptionKey := GenerateKeyPair(ffi.Str2BigInt(party1Key.PaillierPriv.P), ffi.Str2BigInt(party1Key.PaillierPriv.Q))
	partialSig := ffi.Str2BigInt(rst2.PartialSig.C3)
	rst, err := decryptionKey.Decrypt(partialSig)
	assert.Nil(t, err)

	input3 := ffi.Round3Input{
		PlainSig: rst.String(),
		R1Rst:    rst1,
		R2Rst:    rst2,
	}

	rst3 := ffi.Round3(input3)
	assert.NotNil(t, rst3)

	pub_x := `112798640068440206981992607966444350325556905801745747125851303007560154325621`
	pub_y := `106981805274534110405946749712747093099033643902510644172260461166287121657267`

	x := new(big.Int)
	x.SetString(pub_x, 10)

	y := new(big.Int)
	y.SetString(pub_y, 10)
	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     x,
		Y:     y,
	}

	rx := new(big.Int)
	rx.SetString(rst3.Sig.R, 10)

	sumS := new(big.Int)
	sumS.SetString(rst3.Sig.S, 10)

	msg := new(big.Int)
	msg.SetString(input2.Message, 10)

	ok := ecdsa.Verify(&pk, msg.Bytes(), rx, sumS)
	assert.True(t, ok, "signature verification failed")
}

func TestLindellWithTssData(t *testing.T) {
	keys, signPIDs, err := signing.LoadKeygenTestFixtures(2)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, 2, len(keys))
	assert.Equal(t, 2, len(signPIDs))

	key1 := keygen.BuildLocalSaveDataSubset(keys[0], signPIDs)
	key2 := keygen.BuildLocalSaveDataSubset(keys[1], signPIDs)
	msg := big.NewInt(42)

	// round1
	rst1 := ffi.Round1()
	assert.NotNil(t, rst1)

	secretShare1 := signing.PrepareForSigning(tss.S256(), signPIDs[0].Index, len(key1.Ks), key1.Xi, key1.Ks)
	encryptedShare, _, err := key1.PaillierSK.EncryptAndReturnRandomness(secretShare1)
	assert.Nil(t, err)

	paillierPubKeyN := key1.PaillierSK.N

	// round2
	pubShare := make([]byte, 1, 33)
	pubShare[0] = 3
	pubShare = append(pubShare, key2.ECDSAPub.X().Bytes()...)

	secretShare2 := signing.PrepareForSigning(tss.S256(), signPIDs[1].Index, len(key2.Ks), key2.Xi, key2.Ks)

	input2 := ffi.Round2Input{
		PaillierN:      new(big.Int).SetBytes(paillierPubKeyN.Bytes()).String(),
		EncryptedShare: new(big.Int).SetBytes(encryptedShare.Bytes()).String(),
		EcKeyPairParty2: ffi.EphEcKeyPair{
			PublicShare: ffi.Point{
				Curve: "secp256k1",
				Point: ffi.Bytes2Uint(pubShare),
			},
			SecretShare: ffi.Scalar{
				Curve:  "secp256k1",
				Scalar: ffi.Bytes2Uint(secretShare2.Bytes()),
			},
		},
		Message:                 msg.String(),
		EphPartyOneFirstMessage: rst1.EphPartyOneFirstMessage,
	}

	rst2 := ffi.Round2(input2)
	assert.NotNil(t, rst2)

	// round3
	partialSig := ffi.Str2BigInt(rst2.PartialSig.C3)
	rst, err := key1.PaillierSK.Decrypt(partialSig)
	assert.Nil(t, err)

	input3 := ffi.Round3Input{
		PlainSig: rst.String(),
		R1Rst:    rst1,
		R2Rst:    rst2,
	}

	rst3 := ffi.Round3(input3)
	assert.NotNil(t, rst3)

	// verify
	pk := ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     key1.ECDSAPub.X(),
		Y:     key1.ECDSAPub.Y(),
	}

	rx := new(big.Int)
	rx.SetString(rst3.Sig.R, 10)

	sumS := new(big.Int)
	sumS.SetString(rst3.Sig.S, 10)

	ok := ecdsa.Verify(&pk, msg.Bytes(), rx, sumS)
	assert.True(t, ok, "signature verification failed")
}

func GenerateKeyPair(p, q *big.Int) (privateKey *paillier.PrivateKey) {
	one := big.NewInt(1)

	tmp := new(big.Int)
	N := tmp.Mul(p, q)

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey := &paillier.PublicKey{N: N}
	privateKey = &paillier.PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN}
	return
}