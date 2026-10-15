package main

// wlcheck.go — per-wallet OpenSea allowlist (WL) eligibility, extracted from Mugetsu's engine_wlcheck.go.
//
// For each wallet: log it into OpenSea with Sign-In-With-Ethereum (signed locally with the wallet key) on
// its OWN cookie jar, plant the connected-account-server-hint cookie, then read DropEligibilityQuery from
// gql.opensea.io. All of that is required, or isEligible comes back null (ACTIVE_ADDRESS_NOT_PROVIDED).
// A null / failed read is reported as "Error" (couldn't determine) — NEVER a false "Not eligible".

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	osGqlURL        = "https://gql.opensea.io/graphql"
	osSiweStatement = "Click to sign in and accept the OpenSea Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy)."
	browserUA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	zeroAddress     = "0x0000000000000000000000000000000000000000"
)

// osEligQuery is our own DropEligibilityQuery document. gql.opensea.io is an Automatic-Persisted-Query
// endpoint: a hash-only request is served only by nodes that still cache that hash (~80% returned
// 400 PERSISTED_QUERY_NOT_FOUND). Sending the full document + its own sha256 lets any node serve it.
// isEligible takes no argument — OpenSea resolves it from the session + hint cookie.
const osEligQuery = `query DropEligibilityQuery($collectionSlug: String!) {
  dropBySlug(slug: $collectionSlug) {
    __typename
    stages {
      stageType
      stageIndex
      isEligible
      maxTotalMintableByWallet
      eligibleMaxTotalMintableByWallet
    }
  }
}`

func osEligQueryHash() string {
	h := sha256.Sum256([]byte(osEligQuery))
	return hex.EncodeToString(h[:])
}

// ── public types ──────────────────────────────────────────────────────────────

type WlCheckResult struct {
	Address  string   `json:"address"`
	Status   string   `json:"status"`   // "Eligible" | "Not eligible" | "Error" | "Stopped"
	Phase    string   `json:"phase"`    // best phase label, or the error reason
	Eligible []string `json:"eligible"` // phase keys this wallet can mint (see WlPhase.Key)
}

type WlPhase struct {
	Key   string `json:"key"`   // stable id "s<stageIndex>" — matches WlCheckResult.Eligible
	Name  string `json:"name"`  // "Allowlist" / "Public" / the drop's own stage name
	Type  string `json:"type"`  // "allowlist" | "public"
	Cap   int64  `json:"cap"`   // max mints per wallet in this phase
	Index int64  `json:"index"` // OpenSea stageIndex
}

type WlReport struct {
	Slug    string          `json:"slug"`
	Phases  []WlPhase       `json:"phases"`
	Results []WlCheckResult `json:"results"`
}

// Wallet = an address + the private key that signs its OpenSea login.
type Wallet struct {
	Address string
	Key     *ecdsa.PrivateKey
}

type osStage struct {
	IsPublic bool
	Eligible *bool // nil = session didn't apply (treat as "couldn't determine")
	Cap      int64
	Type     string // raw stageType e.g. SIGNED_PRESALE / PUBLIC_SALE
	Index    int64
}

// ── OpenSea session cache (in memory) ────────────────────────────────────────
// Mugetsu persists these DPAPI-encrypted for ~80 h so repeat checks skip the login. This standalone
// version keeps them in memory only (an OpenSea session cookie is account-hijack material, so it is
// never written to disk here). Within one run, a wallet logs in at most once.

type osSession struct {
	cookies []*http.Cookie
	expires time.Time
}

var osSessions sync.Map // lowercase address → osSession

func getOsSession(addr string) (osSession, bool) {
	v, ok := osSessions.Load(strings.ToLower(addr))
	if !ok {
		return osSession{}, false
	}
	s := v.(osSession)
	if len(s.cookies) == 0 || time.Now().After(s.expires) {
		return osSession{}, false
	}
	return s, true
}

func putOsSession(addr string, cookies []*http.Cookie, expires time.Time) {
	if len(cookies) > 0 {
		osSessions.Store(strings.ToLower(addr), osSession{cookies: cookies, expires: expires})
	}
}

// ── SIWE login + eligibility read ────────────────────────────────────────────

// osReqHeaders makes a request look first-party (the session + active address only apply then).
func osReqHeaders(r *http.Request) {
	r.Header.Set("Origin", "https://opensea.io")
	r.Header.Set("Referer", "https://opensea.io/")
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Accept", "application/json")
}

// personalSign EIP-191 signs a message with the wallet key (V normalized to 27/28).
func personalSign(msg string, key *ecdsa.PrivateKey) (string, error) {
	sig, err := crypto.Sign(accounts.TextHash([]byte(msg)), key)
	if err != nil {
		return "", err
	}
	sig[64] += 27
	return hexutil.Encode(sig), nil
}

// osRateErr = an OpenSea 429 (per-IP auth rate limit) carrying the server's suggested cool-off.
type osRateErr struct {
	where      string
	retryAfter time.Duration
}

func (e *osRateErr) Error() string { return "siwe " + e.where + " 429" }

func parseRetryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if d, err := time.ParseDuration(v + "s"); err == nil && d > 0 {
		return d
	}
	return 0
}

// osLoginPace spaces SIWE login starts across all workers — OpenSea's auth endpoint is per-IP
// rate-limited to roughly one at a time; a minimum gap prevents a 429 storm.
var (
	osLoginMu   sync.Mutex
	osLoginLast time.Time
	osLoginLock sync.Map // per-wallet mutex so the same wallet never logs in twice concurrently
)

func osLoginPace() {
	osLoginMu.Lock()
	const minGap = 550 * time.Millisecond
	if wait := minGap - time.Since(osLoginLast); wait > 0 {
		time.Sleep(wait)
	}
	osLoginLast = time.Now()
	osLoginMu.Unlock()
}

// osSiweLogin runs nonce → sign → verify; the client's cookie jar captures the session.
func osSiweLogin(cl *http.Client, address string, chainID int64, key *ecdsa.PrivateKey) error {
	osLoginPace()
	nreq, _ := http.NewRequest("POST", "https://opensea.io/__api/auth/siwe/nonce", nil)
	osReqHeaders(nreq)
	nresp, err := cl.Do(nreq)
	if err != nil {
		return err
	}
	defer nresp.Body.Close()
	if nresp.StatusCode == 429 {
		return &osRateErr{"nonce", parseRetryAfter(nresp.Header)}
	}
	if nresp.StatusCode != 200 {
		return fmt.Errorf("siwe nonce %d", nresp.StatusCode)
	}
	var nr struct {
		Nonce string `json:"nonce"`
	}
	if json.NewDecoder(nresp.Body).Decode(&nr); nr.Nonce == "" {
		return fmt.Errorf("siwe nonce empty")
	}

	issuedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	chainStr := fmt.Sprint(chainID)
	fields := map[string]any{
		"domain": "opensea.io", "address": address, "statement": osSiweStatement,
		"uri": "https://opensea.io", "version": "1", "chainId": chainStr,
		"nonce": nr.Nonce, "issuedAt": issuedAt, "accountType": "Ethereum",
	}
	msg := fmt.Sprintf("opensea.io wants you to sign in with your Ethereum account:\n%s\n\n%s\n\nURI: https://opensea.io\nVersion: 1\nChain ID: %s\nNonce: %s\nIssued At: %s",
		address, osSiweStatement, chainStr, nr.Nonce, issuedAt)
	sig, err := personalSign(msg, key)
	if err != nil {
		return err
	}
	vb, _ := json.Marshal(map[string]any{"message": fields, "signature": sig, "chainArch": "EVM", "connectorId": "io.metamask"})
	vreq, _ := http.NewRequest("POST", "https://opensea.io/__api/auth/siwe/verify", bytes.NewReader(vb))
	osReqHeaders(vreq)
	vreq.Header.Set("Content-Type", "application/json")
	vresp, err := cl.Do(vreq)
	if err != nil {
		return err
	}
	defer vresp.Body.Close()
	if vresp.StatusCode == 429 {
		return &osRateErr{"verify", parseRetryAfter(vresp.Header)}
	}
	if vresp.StatusCode != 200 {
		return fmt.Errorf("siwe verify %d", vresp.StatusCode)
	}
	return nil
}

// osDropEligibility reads the drop's stages for this session ("no stages" = not an OpenSea drop).
func osDropEligibility(cl *http.Client, slug string) ([]osStage, error) {
	body, _ := json.Marshal(map[string]any{
		"operationName": "DropEligibilityQuery",
		"query":         osEligQuery,
		"variables":     map[string]any{"collectionSlug": slug},
		"extensions":    map[string]any{"persistedQuery": map[string]any{"version": 1, "sha256Hash": osEligQueryHash()}},
	})
	req, _ := http.NewRequest("POST", osGqlURL, bytes.NewReader(body))
	osReqHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-app-id", "os2-web")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gql http %d", resp.StatusCode)
	}
	var d struct {
		Data struct {
			DropBySlug struct {
				Stages []struct {
					StageType                        string `json:"stageType"`
					StageIndex                       int64  `json:"stageIndex"`
					IsEligible                       *bool  `json:"isEligible"`
					MaxTotalMintableByWallet         int64  `json:"maxTotalMintableByWallet"`
					EligibleMaxTotalMintableByWallet int64  `json:"eligibleMaxTotalMintableByWallet"`
				} `json:"stages"`
			} `json:"dropBySlug"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	stages := d.Data.DropBySlug.Stages
	if len(stages) == 0 {
		return nil, fmt.Errorf("no stages")
	}
	out := make([]osStage, 0, len(stages))
	for _, s := range stages {
		cap := s.MaxTotalMintableByWallet
		if cap == 0 {
			cap = s.EligibleMaxTotalMintableByWallet
		}
		out = append(out, osStage{IsPublic: strings.Contains(strings.ToLower(s.StageType), "public"), Eligible: s.IsEligible, Cap: cap, Type: s.StageType, Index: s.StageIndex})
	}
	return out, nil
}

// stagesAuthoritative is false when a WL stage came back null (logged-out / rate-limited read).
func stagesAuthoritative(stages []osStage) bool {
	for _, s := range stages {
		if !s.IsPublic && s.Eligible == nil {
			return false
		}
	}
	return len(stages) > 0
}

// hintedJar = cookies + connected-account-server-hint (tells OpenSea which wallet is "active").
func hintedJar(cookies []*http.Cookie, address string) http.CookieJar {
	jar, _ := cookiejar.New(nil)
	if gu, e := url.Parse(osGqlURL); e == nil {
		ck := append(append([]*http.Cookie{}, cookies...), &http.Cookie{Name: "connected-account-server-hint", Value: strings.ToLower(address)})
		jar.SetCookies(gu, ck)
	}
	return jar
}

// osWalletEligibility resolves ONE wallet's per-stage eligibility: cached session first (no login),
// then a fresh SIWE login with 429-aware retries. Returns (stages, "") or (nil, reason).
func osWalletEligibility(key *ecdsa.PrivateKey, address, slug string, chainID int64, attempts int) ([]osStage, string) {
	if attempts < 1 {
		attempts = 1
	}
	tryCached := func() ([]osStage, string, bool) {
		sess, ok := getOsSession(address)
		if !ok {
			return nil, "", false
		}
		cl := &http.Client{Timeout: 20 * time.Second, Jar: hintedJar(sess.cookies, address)}
		stages, err := osDropEligibility(cl, slug)
		if err == nil && stagesAuthoritative(stages) {
			return stages, "", true
		}
		if err != nil && err.Error() == "no stages" {
			return nil, "not a drop", true
		}
		return nil, "", false
	}
	if st, r, ok := tryCached(); ok {
		return st, r
	}

	lk, _ := osLoginLock.LoadOrStore(strings.ToLower(address), &sync.Mutex{})
	lk.(*sync.Mutex).Lock()
	defer lk.(*sync.Mutex).Unlock()
	if st, r, ok := tryCached(); ok { // another worker may have just logged this wallet in
		return st, r
	}

	gqlURL, _ := url.Parse(osGqlURL)
	lastErr := "couldn't determine"
	for attempt := 1; attempt <= attempts; attempt++ {
		jar, _ := cookiejar.New(nil)
		cl := &http.Client{Timeout: 20 * time.Second, Jar: jar}
		if err := osSiweLogin(cl, address, chainID, key); err != nil {
			lastErr = "login: " + err.Error()
			if re, ok := err.(*osRateErr); ok { // rate-limited: wait out the cool-off, then retry
				wait := re.retryAfter
				if wait <= 0 {
					wait = time.Duration(attempt+2) * 1200 * time.Millisecond
				}
				time.Sleep(wait)
				continue
			}
		} else {
			if u2, e := url.Parse("https://opensea.io/"); e == nil {
				jar.SetCookies(u2, []*http.Cookie{{Name: "connected-account-server-hint", Value: strings.ToLower(address), Domain: "opensea.io", Path: "/"}})
			}
			if gqlURL != nil {
				putOsSession(address, jar.Cookies(gqlURL), time.Now().Add(80*time.Hour))
			}
			stages, err := osDropEligibility(cl, slug)
			if err != nil {
				lastErr = err.Error()
				if lastErr == "no stages" {
					return nil, "not a drop"
				}
			} else if stagesAuthoritative(stages) {
				return stages, ""
			} else {
				lastErr = "session not applied (rate-limited?)"
			}
		}
		time.Sleep(time.Duration(attempt) * 800 * time.Millisecond)
	}
	return nil, lastErr
}

// ── phase names + mapping ────────────────────────────────────────────────────

func capSuffix(cap int64) string {
	if cap <= 0 {
		return ""
	}
	return fmt.Sprintf(" · max %d", cap)
}

// provisionalStatus = the quick live verdict before the named phase list is final.
func provisionalStatus(stages []osStage) (status, phase string) {
	for _, s := range stages {
		if !s.IsPublic && s.Eligible != nil && *s.Eligible {
			return "Eligible", "Allowlist" + capSuffix(s.Cap)
		}
	}
	for _, s := range stages {
		if s.IsPublic {
			return "Eligible", "Public" + capSuffix(s.Cap)
		}
	}
	return "Not eligible", ""
}

type namedStage struct {
	Name         string
	MaxPerWallet int64
}

// fetchDropStageNames reads the drop's own stage names from OpenSea's REST API (needs an API key;
// without one the phases are just "Allowlist 1/2…" and "Public").
func fetchDropStageNames(slug, openseaKey string) []namedStage {
	if slug == "" || strings.TrimSpace(openseaKey) == "" {
		return nil
	}
	req, _ := http.NewRequest("GET", "https://api.opensea.io/api/v2/drops/"+slug, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-KEY", openseaKey)
	req.Header.Set("User-Agent", browserUA)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	type rawStage struct {
		Name              string      `json:"name"`
		DisplayName       string      `json:"display_name"`
		Label             string      `json:"label"`
		MaxMintsPerWallet json.Number `json:"max_mints_per_wallet"`
		MaxTokensPerTx    json.Number `json:"max_tokens_per_transaction"`
		MaxPerWallet      json.Number `json:"max_per_wallet"`
	}
	var d struct {
		Drop struct {
			Stages []rawStage `json:"stages"`
		} `json:"drop"`
		Stages []rawStage `json:"stages"`
	}
	b, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(b, &d) != nil {
		return nil
	}
	raw := d.Drop.Stages
	if len(raw) == 0 {
		raw = d.Stages
	}
	out := make([]namedStage, 0, len(raw))
	for _, s := range raw {
		name := s.DisplayName
		if name == "" {
			name = s.Name
		}
		if name == "" {
			name = s.Label
		}
		var mpw int64
		for _, n := range []json.Number{s.MaxMintsPerWallet, s.MaxTokensPerTx, s.MaxPerWallet} {
			if v, err := n.Int64(); err == nil && v > 0 {
				mpw = v
				break
			}
		}
		out = append(out, namedStage{Name: name, MaxPerWallet: mpw})
	}
	return out
}

// buildWlPhases = the drop's ordered phase list: types/indexes from the gql skeleton, names paired
// positionally from the REST stages. fallback = any wallet's stages if the anonymous read failed.
func buildWlPhases(slug, openseaKey string, fallback []osStage) []WlPhase {
	skel, _ := osDropEligibility(&http.Client{Timeout: 15 * time.Second}, slug)
	if len(skel) == 0 {
		skel = fallback
	}
	if len(skel) == 0 {
		return nil
	}
	sort.Slice(skel, func(i, j int) bool { return skel[i].Index < skel[j].Index })
	named := fetchDropStageNames(slug, openseaKey)
	nAllow, nPub := 0, 0
	for _, s := range skel {
		if s.IsPublic {
			nPub++
		} else {
			nAllow++
		}
	}
	seenA, seenP := 0, 0
	out := make([]WlPhase, 0, len(skel))
	for i, s := range skel {
		p := WlPhase{Key: fmt.Sprintf("s%d", s.Index), Cap: s.Cap, Index: s.Index}
		nm := ""
		if i < len(named) {
			nm = strings.TrimSpace(named[i].Name)
			if p.Cap == 0 {
				p.Cap = named[i].MaxPerWallet
			}
		}
		if strings.EqualFold(nm, "null") || strings.EqualFold(nm, "undefined") {
			nm = ""
		}
		if s.IsPublic {
			p.Type = "public"
			seenP++
			if nm == "" || strings.EqualFold(nm, "public") {
				nm = "Public"
				if nPub > 1 {
					nm = fmt.Sprintf("Public %d", seenP)
				}
			}
		} else {
			p.Type = "allowlist"
			seenA++
			if nm == "" || strings.EqualFold(nm, "allowlist") {
				nm = "Allowlist"
				if nAllow > 1 {
					nm = fmt.Sprintf("Allowlist %d", seenA)
				}
			}
		}
		p.Name = nm
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { // allowlist phases first, public last
		pi, pj := out[i].Type == "public", out[j].Type == "public"
		if pi != pj {
			return !pi
		}
		return out[i].Index < out[j].Index
	})
	return out
}

// mapWalletToPhases: which phase keys a wallet can mint + a best-phase label. Public phases are
// open to every wallet; allowlist phases need an authenticated "eligible".
func mapWalletToPhases(stages []osStage, phases []WlPhase) (status, label string, eligible []string) {
	byIndex := map[int64]osStage{}
	for _, s := range stages {
		byIndex[s.Index] = s
	}
	for _, p := range phases {
		if p.Type == "public" {
			eligible = append(eligible, p.Key)
			continue
		}
		if s, ok := byIndex[p.Index]; ok && s.Eligible != nil && *s.Eligible {
			eligible = append(eligible, p.Key)
		}
	}
	if len(eligible) == 0 {
		return "Not eligible", "", nil
	}
	in := map[string]bool{}
	for _, e := range eligible {
		in[e] = true
	}
	for _, p := range phases {
		if p.Type != "public" && in[p.Key] {
			return "Eligible", p.Name + capSuffix(p.Cap), eligible
		}
	}
	for _, p := range phases {
		if p.Type == "public" && in[p.Key] {
			return "Eligible", p.Name + capSuffix(p.Cap), eligible
		}
	}
	return "Eligible", "", eligible
}

// ── the checker ──────────────────────────────────────────────────────────────

// WlCheckStop aborts a running check (wallets already checked keep their result; the rest → "Stopped").
var WlCheckStop atomic.Bool

// CheckWlEligibility checks every wallet against a drop. progress (optional) gets live per-wallet
// updates: status "Checking" | "Eligible" | "Not eligible" | "Error" | "Stopped".
func CheckWlEligibility(slug string, chainID int64, wallets []Wallet, openseaKey string, progress func(addr, status, phase string)) (*WlReport, error) {
	if chainID == 0 {
		chainID = 1
	}
	emit := func(addr, status, phase string) {
		if progress != nil {
			progress(addr, status, phase)
		}
	}
	// One anonymous probe first: a non-drop would otherwise error every wallet + run the slow retry sweep.
	if _, err := osDropEligibility(&http.Client{Timeout: 15 * time.Second}, slug); err != nil && err.Error() == "no stages" {
		return nil, fmt.Errorf("%q is not an OpenSea drop (no mint stages)", slug)
	}
	WlCheckStop.Store(false)

	type walletElig struct {
		stages []osStage
		reason string
	}
	elig := make([]walletElig, len(wallets))
	check := func(i int, attempts int) {
		w := wallets[i]
		cs := common.HexToAddress(w.Address).Hex() // EIP-55 checksum for SIWE
		stages, reason := osWalletEligibility(w.Key, cs, slug, chainID, attempts)
		elig[i] = walletElig{stages: stages, reason: reason}
		if reason != "" {
			emit(w.Address, "Error", reason)
		} else {
			st, ph := provisionalStatus(stages)
			emit(w.Address, st, ph)
		}
	}

	// Parallel pass: logins are paced globally (osLoginPace), so 10 in flight is safe and makes
	// cached-session reads fast.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for i, w := range wallets {
		emit(w.Address, "Checking", "")
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if WlCheckStop.Load() {
				elig[i] = walletElig{reason: "__stopped__"}
				emit(wallets[i].Address, "Stopped", "")
				return
			}
			check(i, 4)
		}(i)
	}
	wg.Wait()

	// Serial retry sweep: re-check errored wallets one at a time (no rate-limit pressure).
	for i, w := range wallets {
		if WlCheckStop.Load() {
			break
		}
		if r := elig[i].reason; r == "" || r == "__stopped__" || r == "not a drop" {
			continue
		}
		emit(w.Address, "Checking", "")
		check(i, 3)
	}

	var first []osStage
	for i := range elig {
		if len(elig[i].stages) > 0 {
			first = elig[i].stages
			break
		}
	}
	phases := buildWlPhases(slug, openseaKey, first)
	rep := &WlReport{Slug: slug, Phases: phases, Results: make([]WlCheckResult, len(wallets))}
	for i, w := range wallets {
		switch r := elig[i].reason; {
		case r == "__stopped__":
			rep.Results[i] = WlCheckResult{Address: w.Address, Status: "Stopped"}
		case r != "":
			rep.Results[i] = WlCheckResult{Address: w.Address, Status: "Error", Phase: r}
		default:
			st, label, keys := mapWalletToPhases(elig[i].stages, phases)
			rep.Results[i] = WlCheckResult{Address: w.Address, Status: st, Phase: label, Eligible: keys}
		}
	}
	return rep, nil
}
