// Package colossusx is a compatibility-first staging package for the UMA-PoW
// engine. It re-exports the current implementation from consensus/ethash so
// the rest of the codebase can migrate imports and runtime wiring first,
// before moving the implementation files themselves.
package colossusx

import (
	"time"

	"github.com/cypherium/cypher/consensus/ethash"
)

type (
	Mode      = ethash.Mode
	Config    = ethash.Config
	ColossusX = ethash.Ethash
)

const (
	ModeNormal    = ethash.ModeNormal
	ModeShared    = ethash.ModeShared
	ModeTest      = ethash.ModeTest
	ModeFake      = ethash.ModeFake
	ModeFullFake  = ethash.ModeFullFake
	ModeLocalMock = ethash.ModeLocalMock
)

var ErrInvalidDumpMagic = ethash.ErrInvalidDumpMagic

func New(config Config) *ColossusX {
	return ethash.New(config)
}

func NewTester() *ColossusX {
	return ethash.NewTester()
}

func NewFaker() *ColossusX {
	return ethash.NewFaker()
}

func NewFakeFailer(fail uint64) *ColossusX {
	return ethash.NewFakeFailer(fail)
}

func NewFakeDelayer(delay time.Duration) *ColossusX {
	return ethash.NewFakeDelayer(delay)
}

func NewFullFaker() *ColossusX {
	return ethash.NewFullFaker()
}

func NewNormal() *ColossusX {
	return ethash.NewNormal()
}

func MakeCache(block uint64, dir string) {
	ethash.MakeCache(block, dir)
}

func MakeDataset(block uint64, dir string) {
	ethash.MakeDataset(block, dir)
}

func SeedHash(block uint64) []byte {
	return ethash.SeedHash(block)
}
