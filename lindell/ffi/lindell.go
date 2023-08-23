package ffi

/*
#cgo CFLAGS: -I./lindellcore
#cgo LDFLAGS: -L${SRCDIR} -llindellcore
#include <stdlib.h>
#include "lindellcore.h"
*/
import "C"
import (
	"encoding/json"
	"unsafe"
)

func Round1() Round1Result {
	rstCstr := C.lindell_round1()
	rst := C.GoString(rstCstr)

	var round1Rst Round1Result
	if err := json.Unmarshal([]byte(rst), &round1Rst); err != nil {
		panic(err)
	}

	return round1Rst
}

func Round2(input Round2Input) Round2Result {
	data, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}

	inputCstr := C.CString(string(data))
	defer C.free(unsafe.Pointer(inputCstr))

	rstCstr := C.lindell_round2(inputCstr)
	rst := C.GoString(rstCstr)

	var round2Rst Round2Result
	if err = json.Unmarshal([]byte(rst), &round2Rst); err != nil {
		panic(err)
	}

	return round2Rst
}

func Round3(input Round3Input) Round3Result {
	data, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}

	inputCstr := C.CString(string(data))
	defer C.free(unsafe.Pointer(inputCstr))

	rstCstr := C.lindell_round3(inputCstr)
	rst := C.GoString(rstCstr)

	var round3Rst Round3Result
	if err = json.Unmarshal([]byte(rst), &round3Rst); err != nil {
		panic(err)
	}

	return round3Rst
}
