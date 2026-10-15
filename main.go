package main

// main.go — command-line front end for the WL checker.
//
//   wlchecker <opensea link | collection slug | contract address> [flags]
//
//   -keys     file with one private key per line (default keys.txt; # starts a comment)
//   -chain    chain name: ethereum, base, arbitrum, optimism, polygon, apechain, abstract, robinhood,
//             ink, hyperevm, arc, sepolia (default ethereum) — used for the sign-in and contract lookup
//   -apikey   OpenSea API key (optional): needed for a contract address, and gives real phase names
//   -json     also write the full report to this file
//
// Ctrl+C once = stop (wallets already checked keep their result; the report still prints).

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

var chainIDByName = map[string]int64{
	"ethereum": 1, "base": 8453, "arbitrum": 42161, "optimism": 10, "polygon": 137, "apechain": 33139,
	"abstract": 2741, "robinhood": 4663, "ink": 57073, "hyperevm": 999, "arc": 5042, "sepolia": 11155111,
}

// OpenSea's chain slugs where they differ from ours (used for the contract → collection lookup).
var openseaChain = map[string]string{"ethereum": "ethereum", "robinhood": "robinhood", "hyperevm": "hyperevm"}

var (
	reCollection = regexp.MustCompile(`(?i)opensea\.io/(?:[a-z-]+/)?collection/([a-z0-9_-]+)`)
	reAddress    = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	reSlug       = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

func main() {
	keysFile := flag.String("keys", "keys.txt", "file with one private key per line")
	chain := flag.String("chain", "ethereum", "chain name")
	apiKey := flag.String("apikey", os.Getenv("OPENSEA_API_KEY"), "OpenSea API key (optional)")
	jsonOut := flag.String("json", "", "write the full report as JSON to this file")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wlchecker <opensea link | slug | contract> [-keys keys.txt] [-chain ethereum] [-apikey KEY] [-json out.json]")
		flag.PrintDefaults()
	}
	// allow flags after the positional argument too
	var pos []string
	args := os.Args[1:]
	for len(args) > 0 {
		flag.CommandLine.Parse(args)
		args = flag.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	if len(pos) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	chainKey := strings.ToLower(strings.TrimSpace(*chain))
	chainID := chainIDByName[chainKey]
	if chainID == 0 {
		fail("unknown chain %q", *chain)
	}

	slug, err := resolveSlug(pos[0], chainKey, *apiKey)
	if err != nil {
		fail("%v", err)
	}
	wallets, err := loadWallets(*keysFile)
	if err != nil {
		fail("%v", err)
	}
	fmt.Printf("Drop: %s   wallets: %d   chain: %s\n\n", slug, len(wallets), chainKey)

	// Ctrl+C → stop gracefully (second Ctrl+C quits immediately).
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Println("\nStopping… (Ctrl+C again to quit now)")
		WlCheckStop.Store(true)
		<-sig
		os.Exit(130)
	}()

	var mu sync.Mutex
	done := 0
	start := time.Now()
	progress := func(addr, status, phase string) {
		if status == "Checking" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		done++
		fmt.Printf("  %-42s %-13s %s\n", addr, status, phase)
	}
	rep, err := CheckWlEligibility(slug, chainID, wallets, *apiKey, progress)
	if err != nil {
		fail("%v", err)
	}

	// ── summary ──
	fmt.Printf("\nPhases:\n")
	for _, p := range rep.Phases {
		fmt.Printf("  %-4s %-28s %-9s%s\n", p.Key, p.Name, p.Type, capSuffix(p.Cap))
	}
	counts := map[string]int{}
	fmt.Printf("\nResults:\n")
	for _, r := range rep.Results {
		counts[r.Status]++
		fmt.Printf("  %-42s %-13s %s\n", r.Address, r.Status, r.Phase)
	}
	fmt.Printf("\n%d eligible · %d not eligible · %d error · %d stopped   (%s)\n",
		counts["Eligible"], counts["Not eligible"], counts["Error"], counts["Stopped"], time.Since(start).Round(time.Second))

	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			fail("write %s: %v", *jsonOut, err)
		}
		fmt.Println("Report saved to", *jsonOut)
	}
}

// resolveSlug turns an OpenSea link, a slug or a contract address into the collection slug.
func resolveSlug(in, chainKey, apiKey string) (string, error) {
	in = strings.TrimSpace(in)
	if m := reCollection.FindStringSubmatch(in); m != nil {
		return strings.ToLower(m[1]), nil
	}
	if reAddress.MatchString(in) {
		if apiKey == "" {
			return "", fmt.Errorf("a contract address needs an OpenSea API key (-apikey); or pass the OpenSea link/slug instead")
		}
		osChain := openseaChain[chainKey]
		if osChain == "" {
			osChain = chainKey
		}
		req, _ := http.NewRequest("GET", "https://api.opensea.io/api/v2/chain/"+osChain+"/contract/"+in, nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-API-KEY", apiKey)
		req.Header.Set("User-Agent", browserUA)
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("contract lookup failed (http %d) — check -chain and -apikey", resp.StatusCode)
		}
		var d struct {
			Collection string `json:"collection"`
		}
		if json.NewDecoder(resp.Body).Decode(&d) != nil || d.Collection == "" {
			return "", fmt.Errorf("no OpenSea collection for that contract on %s", chainKey)
		}
		return d.Collection, nil
	}
	if s := strings.ToLower(in); reSlug.MatchString(s) {
		return s, nil
	}
	return "", fmt.Errorf("%q isn't an OpenSea collection link, slug or contract address", in)
}

// loadWallets reads private keys (one per line; blank lines and # comments ignored).
func loadWallets(path string) ([]Wallet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("can't open keys file %s: %v", path, err)
	}
	defer f.Close()
	var out []Wallet
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		t := strings.TrimSpace(sc.Text())
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" {
			continue
		}
		k, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X"))
		if err != nil {
			return nil, fmt.Errorf("%s line %d: not a valid private key", path, line) // never echo the key
		}
		addr := crypto.PubkeyToAddress(k.PublicKey).Hex()
		if !seen[addr] {
			seen[addr] = true
			out = append(out, Wallet{Address: addr, Key: k})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no private keys found in %s", path)
	}
	return out, sc.Err()
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
