use curv::elliptic::curves::Point;
use curv::BigInt;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::{
    EphEcKeyPair, EphKeyGenFirstMsg, Party1Private, Signature,
};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::{
    EphKeyGenSecondMsg, PartialSig,
};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use paillier::{Decrypt, EncryptionKey, MinimalEncryptionKey, Paillier, RawCiphertext};
use serde::{Deserialize, Serialize};
use std::str;

#[derive(Serialize, Clone, Debug, Deserialize)]
pub struct Round1Result {
    pub eph_party_one_first_message: EphKeyGenFirstMsg,
    pub eph_ec_key_pair_party1: EphEcKeyPair,
}

pub fn round_1() -> Round1Result {
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();

    return Round1Result {
        eph_party_one_first_message,
        eph_ec_key_pair_party1,
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2Input {
    #[serde(with = "paillier::serialize::bigint")]
    pub paillier_n: BigInt,
    #[serde(with = "paillier::serialize::bigint")]
    pub encrypted_share: BigInt,
    pub ec_key_pair_party2: party_two::EcKeyPair,
    #[serde(with = "paillier::serialize::bigint")]
    pub message: BigInt,
    pub eph_party_one_first_message: EphKeyGenFirstMsg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2Result {
    pub eph_party_two_first_message: party_two::EphKeyGenFirstMsg,
    pub eph_party_two_second_message: EphKeyGenSecondMsg,
    pub partial_sig: PartialSig,
}

pub fn round_2(input: Round2Input) -> Round2Result {
    let party2_private = party_two::Party2Private::set_private_key(&input.ec_key_pair_party2); // init

    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments(); // round2-1

    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &input.eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed"); // round2-2

    let ek = EncryptionKey::from(MinimalEncryptionKey {
        n: input.paillier_n,
    });
    let partial_sig = party_two::PartialSig::compute_add(
        &ek,
        &input.encrypted_share,
        &party2_private,
        &eph_ec_key_pair_party2,
        &input.eph_party_one_first_message.public_share,
        &input.message,
    ); // round2-3

    return Round2Result {
        eph_party_two_first_message,
        eph_party_two_second_message,
        partial_sig,
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round3Input {
    #[serde(with = "paillier::serialize::bigint")]
    pub plain_sign: BigInt,
    pub r1_rst: Round1Result,
    pub r2_rst: Round2Result,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round3Result {
    pub signature: Signature,
}

pub fn round_3(input: Round3Input) -> Round3Result {
    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &input.r2_rst.eph_party_two_first_message,
            &input.r2_rst.eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");

    let sig = party_one::Signature::compute_with_plain_msg(
        &input.plain_sign,
        &input.r1_rst.eph_ec_key_pair_party1,
        &input
            .r2_rst
            .eph_party_two_second_message
            .comm_witness
            .public_share,
    );

    return Round3Result { signature: sig };
}

#[test]
fn test_d_log_proof_party_two_party_one() {
    let rst1 = round_1();

    let input2_str = "{\"paillier_n\":\"15453108137667850587026384497369588865052224775570073725993309326495366523991669206594399207496819200050463624967544836174921258210946815255126405995904187130079198265007890408276492485325130874361633623833170726648447821755086459130526921389779073845890531117209524092785802556441822851554867095637818673869236231078603663281248644223479862002646466553476539972565546380447956264804378369256642411505855507008568567051868798770287109216353835717570031675747781261606712855763686428159564736800030834961303392259612397748382955459413473582577117823704304895661889400916964043543607902849223273926561334516746628034783\",\"encrypted_share\":\"224782462767766316063514392915806803306948787831544068973106627706499051452139613639860330722317327231801136772875818625329509582138471570913018611340987335851345926453409529027964142318152523480564343140794564136207674077934544806177748578103733236631142482097993345774944014318734171435579799308278354425452731363685470113467620065957585557703278552337226286241636304322746729479429377673503869788349324069441090748949647067805881135558245256898168503596644535903939834008019863670190068405477143199106354272993395238189346830967717369286699932465234794587745811912814260032513257800001260623967943711074315025288622738571057221532810544685576697488701226489425417565322245556930841349991943548120033411697854106657816395326286833470470590699754973034969769756191564341870048505805606350610158175890189343765725466567143323731777466985177176415400635104213585105711894882617325771852764384254004593570593972516665035267382121098352474159297496430199004169572901446142258301092845625962480565264991329540467223408195134516642080929962584028537381251245980851978631797054206885173854379823630768218449251738815245723084643538580652139558956320113455127612786581302487358347604942320954133124792668132363172076784375922534482460882429\",\"ec_key_pair_party2\":{\"public_share\":{\"curve\":\"secp256k1\",\"point\":[2,238,123,166,171,233,61,177,230,244,73,80,218,189,232,247,6,118,49,191,3,114,46,145,0,143,236,252,236,234,27,178,99]},\"secret_share\":{\"curve\":\"secp256k1\",\"scalar\":[143,203,149,110,22,138,19,21,48,112,240,197,233,13,97,186,27,140,87,111,83,127,48,89,166,106,107,253,143,59,193,0]}},\"message\":\"1234\",\"eph_party_one_first_message\":{\"d_log_proof\":{\"a1\":{\"curve\":\"secp256k1\",\"point\":[3,53,217,97,4,6,87,153,130,83,57,243,224,191,30,222,5,16,153,132,91,2,223,224,55,125,82,239,102,228,134,243,116]},\"a2\":{\"curve\":\"secp256k1\",\"point\":[3,170,79,90,170,129,186,111,62,149,168,2,119,112,202,77,132,57,77,57,222,88,191,110,38,107,169,198,149,15,111,76,207]},\"z\":{\"curve\":\"secp256k1\",\"scalar\":[40,221,85,146,35,105,174,65,212,190,15,242,67,170,131,60,122,183,233,248,142,173,137,64,121,49,244,255,107,87,62,202]}},\"public_share\":{\"curve\":\"secp256k1\",\"point\":[3,211,151,28,250,107,5,240,68,143,198,212,167,167,61,170,37,17,14,1,101,127,185,42,239,198,86,100,57,109,247,174,179]},\"c\":{\"curve\":\"secp256k1\",\"point\":[2,175,41,153,212,173,142,253,56,197,124,116,175,15,106,133,122,101,177,102,166,181,41,118,125,117,34,67,128,167,157,21,239]}}}";
    let mut input2: Round2Input = serde_json::from_str(input2_str).unwrap();
    input2.eph_party_one_first_message.d_log_proof =
        rst1.eph_party_one_first_message.d_log_proof.clone();
    input2.eph_party_one_first_message.public_share =
        rst1.eph_party_one_first_message.public_share.clone();
    input2.eph_party_one_first_message.c = rst1.eph_party_one_first_message.c.clone();

    let msg = input2.message.clone();
    let pub_share = input2.ec_key_pair_party2.public_share.clone();
    let rst2 = round_2(input2);

    let party1_key_str = "{\"x1\":{\"curve\":\"secp256k1\",\"scalar\":[18,145,53,92,155,177,161,193,151,116,192,33,113,184,47,23,76,102,5,110,75,79,154,76,77,9,28,149,22,235,214,209]},\"paillier_priv\":{\"p\":\"137011065195882922300331368001124313983722327643321832355387496023829485899993048330000017579700347702398965702182351207641733095878161311153387201159340422359915255532041342700874486900841091388351490714037782113844110184190722438431436946754041452387471603524895220159558480675144819323831804616587549636411\",\"q\":\"112787300175899987568204194294559966800216308794713588076591241431546999257357980322596241227313565675472577125532179773886338223615893842734094102260801848172811071446946449235647980815311732428704660910538769529774854227799108753801288525671836232275839107991168264533934073486258720450292271840905837755053\"},\"c_key_randomness\":\"72700639327511104965518183215788693417369684139372843655204273831077899050196979418250116449888337729314601081637387142524647477349366917575113493550047580642932173550950821754921369061449425094934792628192156624456476886854898636533282240253993802283810929414745024109725595874942824203071611125645239075164722057779961512009564778405973532672913311407995891025091185476921004862378022800977918272469643004259540878397000284510353880925131073595282423731088207150616088814003315811649626045390727319979557248704425194548209877025032762392807515163442988899619059048083923052903643887749570758410138238321095016990\"}";
    let party1_key: Party1Private = serde_json::from_str(party1_key_str).unwrap();
    let plain_text = Paillier::decrypt(
        &party1_key.paillier_priv,
        &RawCiphertext::from(rst2.clone().partial_sig.c3),
    )
    .0;

    let input3 = Round3Input {
        plain_sign: plain_text.into_owned(),
        r1_rst: rst1,
        r2_rst: rst2,
    };
    let rst3 = round_3(input3);

    let party1_pub_share = Point::generator() * party1_key.x1;
    let pubkey = party_one::compute_add_pubkey(&party1_pub_share, &pub_share);
    party_one::verify(&rst3.signature, &pubkey, &msg).expect("Invalid signature")
}
