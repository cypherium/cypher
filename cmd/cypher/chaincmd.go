// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/cmd/utils"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/console/prompt"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/metrics"
	"github.com/cypherium/cypher/trie"
	cli "gopkg.in/urfave/cli.v1"
)

var (
	initCommand = cli.Command{
		Action:    utils.MigrateFlags(initGenesis),
		Name:      "init",
		Usage:     "Bootstrap and initialize a new genesis block",
		ArgsUsage: "<genesisPath>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The init command initializes a new genesis block and definition for the network.
This is a destructive action and changes the network in which you will be
participating.

It expects the genesis file as argument.`,
	}
	dumpGenesisCommand = cli.Command{
		Action:    utils.MigrateFlags(dumpGenesis),
		Name:      "dumpgenesis",
		Usage:     "Dumps genesis block JSON configuration to stdout",
		ArgsUsage: "",
		Flags: []cli.Flag{
			utils.DataDirFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The dumpgenesis command dumps the genesis block configuration in JSON format to stdout.`,
	}
	importCommand = cli.Command{
		Action:    utils.MigrateFlags(importChain),
		Name:      "import",
		Usage:     "Import a blockchain file",
		ArgsUsage: "<filename> (<filename 2> ... <filename N>) ",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			utils.SyncModeFlag,
			utils.GCModeFlag,
			utils.SnapshotFlag,
			utils.CacheDatabaseFlag,
			utils.CacheGCFlag,
			utils.MetricsEnabledFlag,
			utils.MetricsEnabledExpensiveFlag,
			utils.MetricsHTTPFlag,
			utils.MetricsPortFlag,
			utils.MetricsEnableInfluxDBFlag,
			utils.MetricsInfluxDBEndpointFlag,
			utils.MetricsInfluxDBDatabaseFlag,
			utils.MetricsInfluxDBUsernameFlag,
			utils.MetricsInfluxDBPasswordFlag,
			utils.MetricsInfluxDBTagsFlag,
			utils.TxLookupLimitFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The import command imports blocks from an RLP-encoded form. The form can be one file
with several RLP-encoded blocks, or several files can be used.

If only one file is used, import error will result in failure. If several files are used,
processing will proceed even if an individual RLP-file import failure occurs.`,
	}
	exportCommand = cli.Command{
		Action:    utils.MigrateFlags(exportChain),
		Name:      "export",
		Usage:     "Export blockchain into file",
		ArgsUsage: "<filename> [<blockNumFirst> <blockNumLast>]",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			utils.SyncModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
Requires a first argument of the file to write to.
Optional second and third arguments control the first and
last block to write. In this mode, the file will be appended
if already existing. If the file ends with .gz, the output will
be gzipped.`,
	}
	importPreimagesCommand = cli.Command{
		Action:    utils.MigrateFlags(importPreimages),
		Name:      "import-preimages",
		Usage:     "Import the preimage database from an RLP stream",
		ArgsUsage: "<datafile>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			utils.SyncModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The import-preimages command imports hash preimages from an RLP encoded stream.`,
	}
	exportPreimagesCommand = cli.Command{
		Action:    utils.MigrateFlags(exportPreimages),
		Name:      "export-preimages",
		Usage:     "Export the preimage database into an RLP stream",
		ArgsUsage: "<dumpfile>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			utils.SyncModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The export-preimages command export hash preimages to an RLP encoded stream`,
	}
	copydbCommand = cli.Command{
		Action:    utils.MigrateFlags(copyDb),
		Name:      "copydb",
		Usage:     "Create a local chain from a target chaindata folder",
		ArgsUsage: "<sourceChaindataDir>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			utils.SyncModeFlag,
			utils.FakePoWFlag,
			utils.RopstenFlag,
			utils.RinkebyFlag,
			utils.TxLookupLimitFlag,
			utils.GoerliFlag,
			utils.YoloV1Flag,
			utils.LegacyTestnetFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The first argument must be the directory containing the blockchain to download from`,
	}
	removedbCommand = cli.Command{
		Action:    utils.MigrateFlags(removeDB),
		Name:      "removedb",
		Usage:     "Remove blockchain and state databases",
		ArgsUsage: " ",
		Flags: []cli.Flag{
			utils.DataDirFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
Remove blockchain and state databases`,
	}
	dumpCommand = cli.Command{
		Action:    utils.MigrateFlags(dump),
		Name:      "dump",
		Usage:     "Dump a specific block from storage",
		ArgsUsage: "[<blockHash> | <blockNum>]...",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			utils.SyncModeFlag,
			utils.IterativeOutputFlag,
			utils.ExcludeCodeFlag,
			utils.ExcludeStorageFlag,
			utils.IncludeIncompletesFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The arguments are interpreted as block numbers or hashes.
Use "ethereum dump 0" to dump the genesis block.`,
	}
	inspectCommand = cli.Command{
		Action:    utils.MigrateFlags(inspect),
		Name:      "inspect",
		Usage:     "Inspect the storage size for each type of data in the database",
		ArgsUsage: " ",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.AncientFlag,
			utils.CacheFlag,
			utils.RopstenFlag,
			utils.RinkebyFlag,
			utils.GoerliFlag,
			utils.YoloV1Flag,
			utils.LegacyTestnetFlag,
			utils.SyncModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
	}
)

// initGenesis will initialise the given JSON format genesis file and writes it as
// the zero'd block (i.e. genesis) or will fail hard if it can't succeed.
func initGenesis(ctx *cli.Context) error {
	// Make sure we have a valid genesis JSON
	genesisPath := ctx.Args().First()
	if len(genesisPath) == 0 {
		utils.Fatalf("Must supply path to genesis JSON file")
	}
	file, err := os.Open(genesisPath)
	if err != nil {
		utils.Fatalf("Failed to read genesis file: %v", err)
	}
	defer file.Close()

	keyGenesis := new(core.GenesisKey)
	if err := json.NewDecoder(file).Decode(keyGenesis); err != nil {
		utils.Fatalf("init keychain, invalid genesis file: %v", err)
	}

	file.Seek(0, 0)
	genesis := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		utils.Fatalf("invalid genesis file: %v", err)
	}

	// check the data given as a part of newMaxConfigData to ensure that
	// its in expected order
	err = genesis.Config.CheckMaxCodeConfigData()
	if err != nil {
		utils.Fatalf("maxCodeSize data invalid: %v", err)
	}

	// Open and initialise both full and light databases
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	for _, name := range []string{"chaindata"} {
		chaindb, err := stack.OpenDatabase(name, 0, 0, "")
		if err != nil {
			utils.Fatalf("Failed to open database: %v", err)
		}

		_, hash, err := core.SetupGenesisKeyBlock(chaindb, keyGenesis)
		if err != nil {
			utils.Fatalf("Failed to write genesis key block: %v", err)
		}
		_, hash, err = core.SetupGenesisBlock(chaindb, genesis)
		if err != nil {
			utils.Fatalf("Failed to write genesis block: %v", err)
		}
		chaindb.Close()
		log.Info("Successfully wrote genesis state", "database", name, "hash", hash)
	}
	return nil
}

func dumpGenesis(ctx *cli.Context) error {
	genesis := utils.MakeGenesis(ctx)
	if genesis == nil {
		genesis = core.DefaultGenesisBlock()
	}
	if err := json.NewEncoder(os.Stdout).Encode(genesis); err != nil {
		utils.Fatalf("could not encode genesis")
	}
	return nil
}

func importChain(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		utils.Fatalf("This command requires an argument.")
	}
	// Start metrics export if enabled
	utils.SetupMetrics(ctx)
	// Start system runtime metrics collection
	go metrics.CollectProcessMetrics(3 * time.Second)

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, db := utils.MakeChain(ctx, stack, false, true)
	defer db.Close()

	// Start periodically gathering memory profiles
	var peakMemAlloc, peakMemSys uint64
	go func() {
		stats := new(runtime.MemStats)
		for {
			runtime.ReadMemStats(stats)
			if atomic.LoadUint64(&peakMemAlloc) < stats.Alloc {
				atomic.StoreUint64(&peakMemAlloc, stats.Alloc)
			}
			if atomic.LoadUint64(&peakMemSys) < stats.Sys {
				atomic.StoreUint64(&peakMemSys, stats.Sys)
			}
			time.Sleep(5 * time.Second)
		}
	}()
	// Import the chain
	start := time.Now()

	var importErr error

	if len(ctx.Args()) == 1 {
		if err := utils.ImportChain(chain, ctx.Args().First()); err != nil {
			importErr = err
			log.Error("Import error", "err", err)
		}
	} else {
		for _, arg := range ctx.Args() {
			if err := utils.ImportChain(chain, arg); err != nil {
				importErr = err
				log.Error("Import error", "file", arg, "err", err)
			}
		}
	}
	chain.Stop()
	fmt.Printf("Import done in %v.\n\n", time.Since(start))

	// Output pre-compaction stats mostly to see the import trashing
	stats, err := db.Stat("leveldb.stats")
	if err != nil {
		utils.Fatalf("Failed to read database stats: %v", err)
	}
	fmt.Println(stats)

	ioStats, err := db.Stat("leveldb.iostats")
	if err != nil {
		utils.Fatalf("Failed to read database iostats: %v", err)
	}
	fmt.Println(ioStats)

	// Print the memory statistics used by the importing
	mem := new(runtime.MemStats)
	runtime.ReadMemStats(mem)

	fmt.Printf("Object memory: %.3f MB current, %.3f MB peak\n", float64(mem.Alloc)/1024/1024, float64(atomic.LoadUint64(&peakMemAlloc))/1024/1024)
	fmt.Printf("System memory: %.3f MB current, %.3f MB peak\n", float64(mem.Sys)/1024/1024, float64(atomic.LoadUint64(&peakMemSys))/1024/1024)
	fmt.Printf("Allocations:   %.3f million\n", float64(mem.Mallocs)/1000000)
	fmt.Printf("GC pause:      %v\n\n", time.Duration(mem.PauseTotalNs))

	if ctx.GlobalBool(utils.NoCompactionFlag.Name) {
		return nil
	}

	// Compact the entire database to more accurately measure disk io and print the stats
	start = time.Now()
	fmt.Println("Compacting entire database...")
	if err = db.Compact(nil, nil); err != nil {
		utils.Fatalf("Compaction failed: %v", err)
	}
	fmt.Printf("Compaction done in %v.\n\n", time.Since(start))

	stats, err = db.Stat("leveldb.stats")
	if err != nil {
		utils.Fatalf("Failed to read database stats: %v", err)
	}
	fmt.Println(stats)

	ioStats, err = db.Stat("leveldb.iostats")
	if err != nil {
		utils.Fatalf("Failed to read database iostats: %v", err)
	}
	fmt.Println(ioStats)
	return importErr
}

func exportChain(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		utils.Fatalf("This command requires an argument.")
	}

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, _ := utils.MakeChain(ctx, stack, true, true)
	start := time.Now()

	var err error
	fp := ctx.Args().First()
	if len(ctx.Args()) < 3 {
		err = utils.ExportChain(chain, fp)
	} else {
		// This can be improved to allow for numbers larger than 9223372036854775807
		first, ferr := strconv.ParseInt(ctx.Args().Get(1), 10, 64)
		last, lerr := strconv.ParseInt(ctx.Args().Get(2), 10, 64)
		if ferr != nil || lerr != nil {
			utils.Fatalf("Export error in parsing parameters: block number not an integer\n")
		}
		if first < 0 || last < 0 {
			utils.Fatalf("Export error: block number must be greater than 0\n")
		}
		err = utils.ExportAppendChain(chain, fp, uint64(first), uint64(last))
	}

	if err != nil {
		utils.Fatalf("Export error: %v\n", err)
	}
	fmt.Printf("Export done in %v\n", time.Since(start))
	return nil
}

// importPreimages imports preimage data from the specified file.
func importPreimages(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		utils.Fatalf("This command requires an argument.")
	}

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack)
	start := time.Now()

	if err := utils.ImportPreimages(db, ctx.Args().First()); err != nil {
		utils.Fatalf("Import error: %v\n", err)
	}
	fmt.Printf("Import done in %v\n", time.Since(start))
	return nil
}

// exportPreimages dumps the preimage data to specified json file in streaming way.
func exportPreimages(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		utils.Fatalf("This command requires an argument.")
	}

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack)
	start := time.Now()

	if err := utils.ExportPreimages(db, ctx.Args().First()); err != nil {
		utils.Fatalf("Export error: %v\n", err)
	}
	fmt.Printf("Export done in %v\n", time.Since(start))
	return nil
}

func copyDb(ctx *cli.Context) error {
	// Ensure we have a source chain directory to copy
	if len(ctx.Args()) < 1 {
		utils.Fatalf("Source chaindata directory path argument missing")
	}
	if len(ctx.Args()) < 2 {
		utils.Fatalf("Source ancient chain directory path argument missing")
	}
	// Initialize a new chain for the running node to sync into
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, chainDb := utils.MakeChain(ctx, stack, false, false)
	syncMode := *utils.GlobalTextMarshaler(ctx, utils.SyncModeFlag.Name).(*downloader.SyncMode)

	var syncBloom *trie.SyncBloom
	if syncMode == downloader.FastSync {
		syncBloom = trie.NewSyncBloom(uint64(ctx.GlobalInt(utils.CacheFlag.Name)/2), chainDb)
	}
	dl := downloader.New(0, chainDb, syncBloom, new(event.TypeMux), chain, nil, nil)

	// Create a source peer to satisfy downloader requests from
	db, err := rawdb.NewLevelDBDatabaseWithFreezer(ctx.Args().First(), ctx.GlobalInt(utils.CacheFlag.Name)/2, 256, ctx.Args().Get(1), "")
	if err != nil {
		return err
	}
	hc, err := core.NewHeaderChain(db, chain.Config(), chain.Engine(), func() bool { return false })
	if err != nil {
		return err
	}
	peer := downloader.NewFakePeer("local", db, hc, dl)
	if err = dl.RegisterPeer("local", 63, peer); err != nil {
		return err
	}
	// Synchronise with the simulated peer
	start := time.Now()

	currentHeader := hc.CurrentHeader()
	if err = dl.Synchronise("local", currentHeader.Hash(), hc.GetTd(currentHeader.Hash(), currentHeader.Number.Uint64()), syncMode); err != nil {
		return err
	}
	for dl.Synchronising() {
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Printf("Database copy done in %v\n", time.Since(start))

	// Compact the entire database to remove any sync overhead
	start = time.Now()
	fmt.Println("Compacting entire database...")
	if err = db.Compact(nil, nil); err != nil {
		utils.Fatalf("Compaction failed: %v", err)
	}
	fmt.Printf("Compaction done in %v.\n\n", time.Since(start))
	return nil
}

func removeDB(ctx *cli.Context) error {
	stack, config := makeConfigNode(ctx)

	// Remove the full node state database
	path := stack.ResolvePath("chaindata")
	if common.FileExist(path) {
		confirmAndRemoveDB(path, "full node state database")
	} else {
		log.Info("Full node state database missing", "path", path)
	}
	// Remove the full node ancient database
	path = config.Eth.DatabaseFreezer
	switch {
	case path == "":
		path = filepath.Join(stack.ResolvePath("chaindata"), "ancient")
	case !filepath.IsAbs(path):
		path = config.Node.ResolvePath(path)
	}
	if common.FileExist(path) {
		confirmAndRemoveDB(path, "full node ancient database")
	} else {
		log.Info("Full node ancient database missing", "path", path)
	}
	// Remove the light node database
	path = stack.ResolvePath("lightchaindata")
	if common.FileExist(path) {
		confirmAndRemoveDB(path, "light node database")
	} else {
		log.Info("Light node database missing", "path", path)
	}
	return nil
}

// confirmAndRemoveDB prompts the user for a last confirmation and removes the
// folder if accepted.
func confirmAndRemoveDB(database string, kind string) {
	confirm, err := prompt.Stdin.PromptConfirm(fmt.Sprintf("Remove %s (%s)?", kind, database))
	switch {
	case err != nil:
		utils.Fatalf("%v", err)
	case !confirm:
		log.Info("Database deletion skipped", "path", database)
	default:
		start := time.Now()
		filepath.Walk(database, func(path string, info os.FileInfo, err error) error {
			// If we're at the top level folder, recurse into
			if path == database {
				return nil
			}
			// Delete all the files, but not subfolders
			if !info.IsDir() {
				os.Remove(path)
				return nil
			}
			return filepath.SkipDir
		})
		log.Info("Database successfully deleted", "path", database, "elapsed", common.PrettyDuration(time.Since(start)))
	}
}

func dump(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, chainDb := utils.MakeChain(ctx, stack, true, false)
	defer chainDb.Close()
	for _, arg := range ctx.Args() {
		var block *types.Block
		if hashish(arg) {
			block = chain.GetBlockByHash(common.HexToHash(arg))
		} else {
			num, _ := strconv.Atoi(arg)
			block = chain.GetBlockByNumber(uint64(num))
		}
		if block == nil {
			fmt.Println("{}")
			utils.Fatalf("block not found")
		} else {
			state, err := state.New(block.Root(), state.NewDatabase(chainDb), nil)
			if err != nil {
				utils.Fatalf("could not create new state: %v", err)
			}
			excludeCode := ctx.Bool(utils.ExcludeCodeFlag.Name)
			excludeStorage := ctx.Bool(utils.ExcludeStorageFlag.Name)
			includeMissing := ctx.Bool(utils.IncludeIncompletesFlag.Name)
			if ctx.Bool(utils.IterativeOutputFlag.Name) {
				state.IterativeDump(excludeCode, excludeStorage, !includeMissing, json.NewEncoder(os.Stdout))
			} else {
				if includeMissing {
					fmt.Printf("If you want to include accounts with missing preimages, you need iterative output, since" +
						" otherwise the accounts will overwrite each other in the resulting mapping.")
				}
				fmt.Printf("%v %s\n", includeMissing, state.Dump(excludeCode, excludeStorage, false))
			}
		}
	}
	return nil
}

func inspect(ctx *cli.Context) error {
	node, _ := makeConfigNode(ctx)
	defer node.Close()

	_, chainDb := utils.MakeChain(ctx, node, true, false)
	defer chainDb.Close()

	return rawdb.InspectDatabase(chainDb)
}

// hashish returns true for strings that look like hashes.
func hashish(x string) bool {
	_, err := strconv.Atoi(x)
	return err != nil
}
