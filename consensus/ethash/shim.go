package ethash

import (
	"time"

	"github.com/cypherium/cypher/consensus/colossusx"
)

type (
	Mode   = colossusx.Mode
	Config = colossusx.Config
	Ethash = colossusx.Ethash
)

const (
	ModeNormal    = colossusx.ModeNormal
	ModeShared    = colossusx.ModeShared
	ModeTest      = colossusx.ModeTest
	ModeFake      = colossusx.ModeFake
	ModeFullFake  = colossusx.ModeFullFake
	ModeLocalMock = colossusx.ModeLocalMock
)

var ErrInvalidDumpMagic = colossusx.ErrInvalidDumpMagic

func New(config Config) *Ethash                   { return colossusx.New(config) }
func NewTester() *Ethash                          { return colossusx.NewTester() }
func NewFaker() *Ethash                           { return colossusx.NewFaker() }
func NewFakeFailer(fail uint64) *Ethash           { return colossusx.NewFakeFailer(fail) }
func NewFakeDelayer(delay time.Duration) *Ethash  { return colossusx.NewFakeDelayer(delay) }
func NewFullFaker() *Ethash                       { return colossusx.NewFullFaker() }
func NewNormal() *Ethash                          { return colossusx.NewNormal() }
func MakeCache(block uint64, dir string)          { colossusx.MakeCache(block, dir) }
func MakeDataset(block uint64, dir string)        { colossusx.MakeDataset(block, dir) }
func SeedHash(block uint64) []byte                { return colossusx.SeedHash(block) }
