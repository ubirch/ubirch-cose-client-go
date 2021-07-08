package tests

import (
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
)

const (
	PrivHex = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"                                                                 //"10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	PubHex  = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771" //"92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"

	Auth = "1234"
)

var (
	Uuid      = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")

	Key, _    = hex.DecodeString(PrivHex)
	PubKey, _ = hex.DecodeString(PubHex)

	Error     = errors.New("test error")
)
