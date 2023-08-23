extern crate libc;
use crate::lindell::{
    round_1, round_2, round_3, Round1Result, Round2Input, Round2Result, Round3Input, Round3Result,
};
use std::ffi::{CStr, CString};

#[no_mangle]
pub unsafe extern "C" fn lindell_round1() -> *const libc::c_char {
    let round1_result: Round1Result = round_1();

    let str_round1_rst = serde_json::to_string(&round1_result).unwrap();
    return CString::new(str_round1_rst).unwrap().into_raw();
}

#[no_mangle]
pub unsafe extern "C" fn lindell_round2(input: *const libc::c_char) -> *const libc::c_char {
    let cstr_input = unsafe { CStr::from_ptr(input) };
    let str_input = cstr_input.to_str().unwrap().to_string();
    let round2_input: Round2Input = serde_json::from_str(&str_input).unwrap();

    let round2_result: Round2Result = round_2(round2_input);

    let str_round2_rst = serde_json::to_string(&round2_result).unwrap();
    return CString::new(str_round2_rst).unwrap().into_raw();
}

#[no_mangle]
pub unsafe extern "C" fn lindell_round3(input: *const libc::c_char) -> *const libc::c_char {
    let cstr_input = unsafe { CStr::from_ptr(input) };
    let str_input = cstr_input.to_str().unwrap().to_string();
    let round3_input: Round3Input = serde_json::from_str(&str_input).unwrap();

    let round3_result: Round3Result = round_3(round3_input);

    let str_round3_rst = serde_json::to_string(&round3_result).unwrap();
    return CString::new(str_round3_rst).unwrap().into_raw();
}
