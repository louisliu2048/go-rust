package ffi

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInterfaceType(t *testing.T) {
	rst1Str := `{"eph_party_one_first_message":{"d_log_proof":{"a1":{"curve":"secp256k1","point":[3,136,247,183,232,115,188,25,145,204,55,120,250,204,89,120,12,119,194,124,111,65,47,224,251,220,166,107,122,82,84,122,215]},"a2":{"curve":"secp256k1","point":[2,39,4,146,3,67,171,144,59,165,241,26,141,216,97,149,88,133,106,200,122,54,153,87,76,75,175,70,1,222,93,16,144]},"z":{"curve":"secp256k1","scalar":[153,114,59,70,62,131,43,140,189,170,249,74,205,38,159,91,51,112,37,2,20,148,14,203,36,207,234,117,11,20,167,32]}},"public_share":{"curve":"secp256k1","point":[3,46,2,38,172,180,169,237,145,254,125,231,113,106,203,247,232,226,189,92,156,2,98,210,232,6,153,182,240,150,199,111,27]},"c":{"curve":"secp256k1","point":[2,221,29,155,224,53,30,14,174,86,233,148,175,70,81,225,122,22,132,251,190,11,154,191,125,203,5,199,99,12,31,185,54]}},"eph_ec_key_pair_party1":{"public_share":{"curve":"secp256k1","point":[3,46,2,38,172,180,169,237,145,254,125,231,113,106,203,247,232,226,189,92,156,2,98,210,232,6,153,182,240,150,199,111,27]},"secret_share":{"curve":"secp256k1","scalar":[37,253,164,96,171,51,16,109,9,146,20,3,198,97,208,47,217,161,127,240,22,67,10,203,45,55,136,71,68,25,88,180]}}}`

	var r1Rst Round1Result
	err := json.Unmarshal([]byte(rst1Str), &r1Rst)
	assert.Nil(t, err, " fail to convert str to Round1Result")

	input2Str := `{"paillier_n":"17050169447906512041206342239714547697188551529493618471585410681982412112350829076920740852118339708045680462830515156388111602914400463840800160908789777331618276771036318081610311852066222512577618505893659718824344841598381198913874792785689809277435478463047109378533967299937631236902834878536153504697463886533801495509910572871754891103610661429780681282511870848660634679266024162559961879758677447088917267229480037087412482862060523949108198727118008352087186161758239568479121043005866818087462444348894163489604475291744142444660622886888368926342097403234735588671702721185281150613509520765586783504653","encrypted_share":"241865627276680371147214954629886518559299597689104814904866764586680088288673373010644329987387942639064193715208512113804619037894725484832872859761448017400257510737244004998335422602626720547512507899239269955511615082784276044468286727426357843931333023076739503194622403653247565205943715959720535807106888831268356190928864113098568538615398040881726300508769261937137129640635153075614638420794246117151388813952350128105040728852541174694597339492482862351933507749233183656831880805266145101717679098157029076159817455673358378955153369419051429279646847506191475571073949344259507405242219952604282716246153399246543514231743543386502542312318751481245989090445644946243349758127234223143997371557169769329692665909608478724897776228296718935428250490153572627657722182111653657863782945687776027160446849611653693631974026748673824097741622802314425141791834407117416330014309497188281550409716627927527001376038569033706440489084198750312346016469228671628023260074292394772719119385262721585284605887753275023076095383152834085567531797598895827106908643521114115697547386018381463344846014693840533636566376081601990804059889831533301214892185707731653992258893135164102899783336057792380111217838819853469505801008920","ec_key_pair_party2":{"public_share":{"curve":"secp256k1","point":[2,153,20,120,168,39,132,198,248,95,221,202,124,165,94,58,96,58,212,115,67,109,120,74,66,71,49,107,16,156,100,227,143]},"secret_share":{"curve":"secp256k1","scalar":[115,163,89,15,102,192,230,59,38,224,189,209,243,148,105,107,216,70,211,211,131,249,76,123,23,195,73,79,142,77,25,56]}},"message":"1234","eph_party_one_first_message":{"d_log_proof":{"a1":{"curve":"secp256k1","point":[3,136,247,183,232,115,188,25,145,204,55,120,250,204,89,120,12,119,194,124,111,65,47,224,251,220,166,107,122,82,84,122,215]},"a2":{"curve":"secp256k1","point":[2,39,4,146,3,67,171,144,59,165,241,26,141,216,97,149,88,133,106,200,122,54,153,87,76,75,175,70,1,222,93,16,144]},"z":{"curve":"secp256k1","scalar":[153,114,59,70,62,131,43,140,189,170,249,74,205,38,159,91,51,112,37,2,20,148,14,203,36,207,234,117,11,20,167,32]}},"public_share":{"curve":"secp256k1","point":[3,46,2,38,172,180,169,237,145,254,125,231,113,106,203,247,232,226,189,92,156,2,98,210,232,6,153,182,240,150,199,111,27]},"c":{"curve":"secp256k1","point":[2,221,29,155,224,53,30,14,174,86,233,148,175,70,81,225,122,22,132,251,190,11,154,191,125,203,5,199,99,12,31,185,54]}}}`
	rst2Str := `{"eph_party_two_first_message":{"pk_commitment":"66986376533250027827140837758455093186138254236878683000153115076246179455047","zk_pok_commitment":"38583635392182058497600735620920896690053286875126645934235864970928281739516"},"eph_party_two_second_message":{"comm_witness":{"pk_commitment_blind_factor":"96324591265635270245697217666018851113014093323644433759649116505854915284243","zk_pok_blind_factor":"43537797225161695293523913418531901607310899769913854158667686968069669816015","public_share":{"curve":"secp256k1","point":[3,242,10,189,39,105,28,166,245,176,232,3,19,134,157,18,136,227,16,215,111,101,109,144,56,102,27,162,62,1,90,22,117]},"d_log_proof":{"a1":{"curve":"secp256k1","point":[3,107,184,90,137,204,9,73,172,67,155,55,15,228,84,216,43,24,32,42,93,115,173,147,41,45,222,147,116,246,13,120,91]},"a2":{"curve":"secp256k1","point":[3,100,96,29,212,52,216,48,43,155,94,110,6,184,230,29,88,77,242,78,178,142,243,48,245,77,190,134,108,62,237,178,84]},"z":{"curve":"secp256k1","scalar":[210,143,194,104,243,164,37,213,187,185,167,135,129,196,211,57,78,98,161,144,176,219,27,14,234,109,108,165,124,199,24,8]}},"c":{"curve":"secp256k1","point":[3,201,83,107,54,93,134,126,133,5,53,16,174,133,138,133,247,208,237,74,138,108,140,128,89,174,162,232,171,235,140,127,164]}}},"partial_sig":{"c3":"160527072038713190863270003218982331524509513271322074137979974643615287802143407352204111648385182095134672791764925851307514931630056234016727255251511077320089451436503913375851571895648358273665614280955360832399217080628577625773087203995740633432292988463483571380705429833510470922036899528263561068243958074745738759043914379192905317473253538909865277846359566016783772078254051795474985954432938871373105781997546701754362415687323941599646877430976118262274040203828419082449797746249609939969807355310873131106292479624904371800408338204005702755214576384647926518575443669593665619332942670511599803809082420514340029030991178934382442397365456182651736823154906720823565847296395532715175029120418992736809879647479048840350104923723745898259136238796335696998299384177946687476338200258589178755181447011390400117371586950703514134968895806972148826414823677531548448693073338223969897528397717414947769509245483531375081994459033771430935833986921294711352452906936843684461286131316010740111349134437415165440483968446459650277882929135056674688837127033179197384320705534275699629115788709312135504881892264782337762911476485250606173501698226647629165451962875681873522235610404305262176259318194779226539082738387"}}`

	var r2Input Round2Input
	err = json.Unmarshal([]byte(input2Str), &r2Input)
	assert.Nil(t, err, " fail to convert str to Round2Input")

	var r2Rst Round2Result
	err = json.Unmarshal([]byte(rst2Str), &r2Rst)
	assert.Nil(t, err, " fail to convert str to Round2Result")

	input3Str := `{"plain_sign":"66781981934366929153835120522934990594590677477293090094604317996230320779038365111216421478540068923132329728817153635002573038108307032599985393173072976768836604186949129057018778816992367417004278038962776070083010370430173921","r1_rst":{"eph_party_one_first_message":{"d_log_proof":{"a1":{"curve":"secp256k1","point":[3,136,247,183,232,115,188,25,145,204,55,120,250,204,89,120,12,119,194,124,111,65,47,224,251,220,166,107,122,82,84,122,215]},"a2":{"curve":"secp256k1","point":[2,39,4,146,3,67,171,144,59,165,241,26,141,216,97,149,88,133,106,200,122,54,153,87,76,75,175,70,1,222,93,16,144]},"z":{"curve":"secp256k1","scalar":[153,114,59,70,62,131,43,140,189,170,249,74,205,38,159,91,51,112,37,2,20,148,14,203,36,207,234,117,11,20,167,32]}},"public_share":{"curve":"secp256k1","point":[3,46,2,38,172,180,169,237,145,254,125,231,113,106,203,247,232,226,189,92,156,2,98,210,232,6,153,182,240,150,199,111,27]},"c":{"curve":"secp256k1","point":[2,221,29,155,224,53,30,14,174,86,233,148,175,70,81,225,122,22,132,251,190,11,154,191,125,203,5,199,99,12,31,185,54]}},"eph_ec_key_pair_party1":{"public_share":{"curve":"secp256k1","point":[3,46,2,38,172,180,169,237,145,254,125,231,113,106,203,247,232,226,189,92,156,2,98,210,232,6,153,182,240,150,199,111,27]},"secret_share":{"curve":"secp256k1","scalar":[37,253,164,96,171,51,16,109,9,146,20,3,198,97,208,47,217,161,127,240,22,67,10,203,45,55,136,71,68,25,88,180]}}},"r2_rst":{"eph_party_two_first_message":{"pk_commitment":"66986376533250027827140837758455093186138254236878683000153115076246179455047","zk_pok_commitment":"38583635392182058497600735620920896690053286875126645934235864970928281739516"},"eph_party_two_second_message":{"comm_witness":{"pk_commitment_blind_factor":"96324591265635270245697217666018851113014093323644433759649116505854915284243","zk_pok_blind_factor":"43537797225161695293523913418531901607310899769913854158667686968069669816015","public_share":{"curve":"secp256k1","point":[3,242,10,189,39,105,28,166,245,176,232,3,19,134,157,18,136,227,16,215,111,101,109,144,56,102,27,162,62,1,90,22,117]},"d_log_proof":{"a1":{"curve":"secp256k1","point":[3,107,184,90,137,204,9,73,172,67,155,55,15,228,84,216,43,24,32,42,93,115,173,147,41,45,222,147,116,246,13,120,91]},"a2":{"curve":"secp256k1","point":[3,100,96,29,212,52,216,48,43,155,94,110,6,184,230,29,88,77,242,78,178,142,243,48,245,77,190,134,108,62,237,178,84]},"z":{"curve":"secp256k1","scalar":[210,143,194,104,243,164,37,213,187,185,167,135,129,196,211,57,78,98,161,144,176,219,27,14,234,109,108,165,124,199,24,8]}},"c":{"curve":"secp256k1","point":[3,201,83,107,54,93,134,126,133,5,53,16,174,133,138,133,247,208,237,74,138,108,140,128,89,174,162,232,171,235,140,127,164]}}},"partial_sig":{"c3":"160527072038713190863270003218982331524509513271322074137979974643615287802143407352204111648385182095134672791764925851307514931630056234016727255251511077320089451436503913375851571895648358273665614280955360832399217080628577625773087203995740633432292988463483571380705429833510470922036899528263561068243958074745738759043914379192905317473253538909865277846359566016783772078254051795474985954432938871373105781997546701754362415687323941599646877430976118262274040203828419082449797746249609939969807355310873131106292479624904371800408338204005702755214576384647926518575443669593665619332942670511599803809082420514340029030991178934382442397365456182651736823154906720823565847296395532715175029120418992736809879647479048840350104923723745898259136238796335696998299384177946687476338200258589178755181447011390400117371586950703514134968895806972148826414823677531548448693073338223969897528397717414947769509245483531375081994459033771430935833986921294711352452906936843684461286131316010740111349134437415165440483968446459650277882929135056674688837127033179197384320705534275699629115788709312135504881892264782337762911476485250606173501698226647629165451962875681873522235610404305262176259318194779226539082738387"}}}`
	rst3Str := `{"signature":{"s":"19248029043894904177025693093304372834291043995168008804926546460026688547280","r":"46941081091225036830072387865703010560382060565925475904972390801674502637057"}}`

	var r3Input Round3Input
	err = json.Unmarshal([]byte(input3Str), &r3Input)
	assert.Nil(t, err, " fail to convert str to Round3Input")

	var r3Rst Round3Result
	err = json.Unmarshal([]byte(rst3Str), &r3Rst)
	assert.Nil(t, err, " fail to convert str to Round3Result")
}