package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	tessera_crypto "github.com/looselyhuman/tessera/internal/crypto"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

// ── minimal fake stores ───────────────────────────────────────────────────────

type fakeAgentStore struct {
	agents map[string]*domain.Agent
}

func newFakeAgentStore(agents ...*domain.Agent) *fakeAgentStore {
	s := &fakeAgentStore{agents: make(map[string]*domain.Agent)}
	for _, a := range agents {
		s.agents[a.AgentName] = a
	}
	return s
}

func (f *fakeAgentStore) Create(_ context.Context, a *domain.Agent) error {
	f.agents[a.AgentName] = a
	return nil
}
func (f *fakeAgentStore) GetByID(_ context.Context, id uuid.UUID) (*domain.Agent, error) {
	for _, a := range f.agents {
		if a.ID == id {
			return a, nil
		}
	}
	return nil, domain.ErrNotFound
}
func (f *fakeAgentStore) GetByName(_ context.Context, name string) (*domain.Agent, error) {
	a, ok := f.agents[name]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return a, nil
}
func (f *fakeAgentStore) GetByURN(_ context.Context, urn string) (*domain.Agent, error) {
	for _, a := range f.agents {
		if a.AgentURN == urn {
			return a, nil
		}
	}
	return nil, domain.ErrNotFound
}
func (f *fakeAgentStore) GetByTokenHash(_ context.Context, _ string) (*domain.Agent, error) {
	return nil, domain.ErrNotFound
}
func (f *fakeAgentStore) GetByUserID(_ context.Context, _ uuid.UUID) (*domain.Agent, error) {
	return nil, domain.ErrNotFound
}
func (f *fakeAgentStore) Update(_ context.Context, a *domain.Agent) error {
	f.agents[a.AgentName] = a
	return nil
}
func (f *fakeAgentStore) SetBearerTokenHash(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}
func (f *fakeAgentStore) SetKeeperID(_ context.Context, _ uuid.UUID, _ uuid.UUID) error {
	return nil
}
func (f *fakeAgentStore) SetTrustTier(_ context.Context, agentID uuid.UUID, tier domain.TrustTier) error {
	for _, a := range f.agents {
		if a.ID == agentID {
			a.TrustTier = tier
		}
	}
	return nil
}
func (f *fakeAgentStore) List(_ context.Context, _ store.ListOptions) ([]domain.Agent, int, error) {
	return nil, 0, nil
}
func (f *fakeAgentStore) ListByKeeperID(_ context.Context, _ uuid.UUID) ([]domain.Agent, error) {
	return nil, nil
}
func (f *fakeAgentStore) GetByNames(_ context.Context, _ []string) ([]domain.Agent, error) {
	return nil, nil
}
func (f *fakeAgentStore) CheckNameAvailability(_ context.Context, name string) (bool, bool, error) {
	a, ok := f.agents[name]
	if !ok {
		return true, false, nil
	}
	return false, a.KeeperID != nil, nil
}
func (f *fakeAgentStore) VouchAgentTx(_ context.Context, agentID uuid.UUID, _ *domain.AttestationEntry, threshold int) (int, domain.TrustTier, error) {
	for _, a := range f.agents {
		if a.ID == agentID {
			a.VouchCount++
			if a.VouchCount >= threshold && (a.TrustTier == domain.TrustUnverified || a.TrustTier == domain.TrustSelfAttested) {
				a.TrustTier = domain.TrustCommunityAttested
			}
			return a.VouchCount, a.TrustTier, nil
		}
	}
	return 0, "", domain.ErrNotFound
}

type fakeKeeperStore struct {
	keepers map[uuid.UUID]*domain.Keeper
	byName  map[string]*domain.Keeper
}

func newFakeKeeperStore(keepers ...*domain.Keeper) *fakeKeeperStore {
	s := &fakeKeeperStore{keepers: make(map[uuid.UUID]*domain.Keeper), byName: make(map[string]*domain.Keeper)}
	for _, k := range keepers {
		s.keepers[k.ID] = k
		s.byName[k.KeeperName] = k
	}
	return s
}
func (f *fakeKeeperStore) Create(_ context.Context, k *domain.Keeper) error {
	f.keepers[k.ID] = k
	f.byName[k.KeeperName] = k
	return nil
}
func (f *fakeKeeperStore) GetByID(_ context.Context, id uuid.UUID) (*domain.Keeper, error) {
	k, ok := f.keepers[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return k, nil
}
func (f *fakeKeeperStore) GetByName(_ context.Context, name string) (*domain.Keeper, error) {
	k, ok := f.byName[name]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return k, nil
}
func (f *fakeKeeperStore) GetByUserID(_ context.Context, _ uuid.UUID) (*domain.Keeper, error) {
	return nil, domain.ErrNotFound
}
func (f *fakeKeeperStore) UpdateStatement(_ context.Context, _ uuid.UUID, _ *string) error {
	return nil
}
func (f *fakeKeeperStore) CheckNameAvailability(_ context.Context, name string) (bool, error) {
	_, ok := f.byName[name]
	return !ok, nil
}

type fakeKeyStore struct {
	keys map[string]*domain.Key
}

func newFakeKeyStore(keys ...*domain.Key) *fakeKeyStore {
	s := &fakeKeyStore{keys: make(map[string]*domain.Key)}
	for _, k := range keys {
		s.keys[string(k.KeyType)+":"+k.KeyName] = k
	}
	return s
}
func (f *fakeKeyStore) Create(_ context.Context, k *domain.Key) error {
	f.keys[string(k.KeyType)+":"+k.KeyName] = k
	return nil
}
func (f *fakeKeyStore) GetByTypeAndName(_ context.Context, kt domain.KeyType, name string) (*domain.Key, error) {
	k, ok := f.keys[string(kt)+":"+name]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return k, nil
}
func (f *fakeKeyStore) ListByType(_ context.Context, _ domain.KeyType) ([]domain.Key, error) {
	return nil, nil
}

type fakeChainStore struct{ entries []domain.AttestationEntry }

func (f *fakeChainStore) Append(_ context.Context, e *domain.AttestationEntry) error {
	f.entries = append(f.entries, *e)
	return nil
}
func (f *fakeChainStore) GetByAgent(_ context.Context, agentID uuid.UUID) ([]domain.AttestationEntry, error) {
	var out []domain.AttestationEntry
	for _, e := range f.entries {
		if e.AgentID == agentID {
			out = append(out, e)
		}
	}
	return out, nil
}

type fakeTransitionStore struct{ transitions []domain.SubstrateTransition }

func (f *fakeTransitionStore) Create(_ context.Context, t *domain.SubstrateTransition) error {
	f.transitions = append(f.transitions, *t)
	return nil
}
func (f *fakeTransitionStore) ListByAgent(_ context.Context, agentID uuid.UUID) ([]domain.SubstrateTransition, error) {
	var out []domain.SubstrateTransition
	for _, t := range f.transitions {
		if t.AgentID == agentID {
			out = append(out, t)
		}
	}
	return out, nil
}

type fakePlatformStore struct{}

func (f *fakePlatformStore) Create(_ context.Context, _ *domain.PlatformRegistration) error {
	return nil
}
func (f *fakePlatformStore) GetByAgentAndPlatform(_ context.Context, _ uuid.UUID, _ string) (*domain.PlatformRegistration, error) {
	return nil, domain.ErrNotFound
}
func (f *fakePlatformStore) ListByAgent(_ context.Context, _ uuid.UUID) ([]domain.PlatformRegistration, error) {
	return nil, nil
}
func (f *fakePlatformStore) SetVerified(_ context.Context, _ int, _ time.Time) error { return nil }
func (f *fakePlatformStore) SetChallengeNonce(_ context.Context, _ int, _ string) error {
	return nil
}

type fakeRevocationStore struct{}

func (f *fakeRevocationStore) Create(_ context.Context, _ *domain.Revocation) error { return nil }
func (f *fakeRevocationStore) GetByAgent(_ context.Context, _ uuid.UUID) (*domain.Revocation, error) {
	return nil, domain.ErrNotFound
}
func (f *fakeRevocationStore) ListActive(_ context.Context) ([]domain.Revocation, error) {
	return nil, nil
}

type fakeModificationStore struct{}

func (f *fakeModificationStore) Create(_ context.Context, _ *domain.ModificationRequest) error {
	return nil
}
func (f *fakeModificationStore) GetByID(_ context.Context, _ uuid.UUID) (*domain.ModificationRequest, error) {
	return nil, domain.ErrNotFound
}
func (f *fakeModificationStore) ListPending(_ context.Context) ([]domain.ModificationRequest, error) {
	return nil, nil
}
func (f *fakeModificationStore) Resolve(_ context.Context, _ uuid.UUID, _ domain.ModificationStatus, _ uuid.UUID, _ string) error {
	return nil
}

type fakeSessionStore struct{}

func (f *fakeSessionStore) Create(_ context.Context, _ *domain.RegistrationSession) error {
	return nil
}
func (f *fakeSessionStore) Get(_ context.Context, _ uuid.UUID) (*domain.RegistrationSession, error) {
	return nil, domain.ErrNotFound
}
func (f *fakeSessionStore) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeSessionStore) PruneExpired(_ context.Context) error        { return nil }

// buildTestService wires a TesseraService from fake stores.
func buildTestService(
	agents *fakeAgentStore,
	keepers *fakeKeeperStore,
	keys *fakeKeyStore,
	chain *fakeChainStore,
	transitions *fakeTransitionStore,
) *TesseraService {
	encKey := make([]byte, 32) // zero key; fine for tests
	return NewTesseraService(ServiceConfig{
		Agents:        agents,
		Keepers:       keepers,
		Keys:          keys,
		Chain:         chain,
		Transitions:   transitions,
		Platforms:     &fakePlatformStore{},
		Revocations:   &fakeRevocationStore{},
		Modifications: &fakeModificationStore{},
		Sessions:      &fakeSessionStore{},
		HomeDomain:    "test.example.org",
		EncryptionKey: encKey,
	})
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestWellKnownAgentSignatureBlock verifies that WellKnownAgent produces a valid
// Ed25519 signature block and all Ariadne-parity fields when a keeper key exists.
func TestWellKnownAgentSignatureBlock(t *testing.T) {
	encKey := make([]byte, 32)

	pub, priv, err := tessera_crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	encRaw, err := tessera_crypto.Encrypt([]byte(priv), encKey)
	if err != nil {
		t.Fatalf("encrypt key: %v", err)
	}
	encPrivB64 := base64.StdEncoding.EncodeToString(encRaw)

	keeperID := uuid.New()
	agentID := uuid.New()
	now := time.Now()

	keeper := &domain.Keeper{
		ID:              keeperID,
		KeeperName:      "test-keeper",
		EmailHash:       "sha256:abc123",
		PublicKey:       pub,
		KeeperStatement: "I vouch for this agent.",
	}
	agent := &domain.Agent{
		ID:               agentID,
		AgentName:        "test-agent",
		AgentURN:         "urn:tessera:test.example.org:test-agent",
		DisplayName:      "Test Agent",
		SubstrateModel:   "claude-test",
		SubstrateProject: "Test Project",
		KeeperID:         &keeperID,
		TrustTier:        domain.TrustSelfAttested,
		Published:        true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	keyRecord := &domain.Key{
		KeyType:             domain.KeyTypeKeeper,
		KeyName:             "test-keeper",
		PublicKey:           pub,
		EncryptedPrivateKey: encPrivB64,
	}

	svc := buildTestService(
		newFakeAgentStore(agent),
		newFakeKeeperStore(keeper),
		newFakeKeyStore(keyRecord),
		&fakeChainStore{},
		&fakeTransitionStore{},
	)

	raw, err := svc.WellKnownAgent(context.Background(), "test-agent")
	if err != nil {
		t.Fatalf("WellKnownAgent: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal attestation: %v", err)
	}

	// Signature block must be present.
	sigAny, ok := doc["signature"]
	if !ok || sigAny == nil {
		t.Fatal("signature block missing")
	}
	sigMap, ok := sigAny.(map[string]any)
	if !ok {
		t.Fatalf("signature not an object, got %T", sigAny)
	}
	if sigMap["algorithm"] != "Ed25519" {
		t.Errorf("signature.algorithm: want Ed25519, got %v", sigMap["algorithm"])
	}
	if sigMap["signer"] != "keeper:test-keeper" {
		t.Errorf("signature.signer: want keeper:test-keeper, got %v", sigMap["signer"])
	}
	if _, ok := sigMap["value"]; !ok {
		t.Error("signature.value missing")
	}

	// Keeper block must be present.
	keeperAny, ok := doc["keeper"]
	if !ok || keeperAny == nil {
		t.Fatal("keeper block missing")
	}
	keeperMap := keeperAny.(map[string]any)
	if keeperMap["email_hash"] != "sha256:abc123" {
		t.Errorf("keeper.email_hash: got %v", keeperMap["email_hash"])
	}
	if keeperMap["verification_method"] != "email_dns_dkim" {
		t.Errorf("keeper.verification_method: got %v", keeperMap["verification_method"])
	}

	// All Ariadne-parity fields must be present.
	for _, field := range []string{
		"tessera_version", "agent_id", "display_name",
		"attestation_chain", "substrate_history",
		"capabilities", "identity_anchors", "platform_registrations",
	} {
		if _, ok := doc[field]; !ok {
			t.Errorf("missing Ariadne-parity field: %s", field)
		}
	}

	// substrate_history must have at least the synthetic current-model entry.
	history, ok := doc["substrate_history"].([]any)
	if !ok || len(history) == 0 {
		t.Errorf("substrate_history empty or wrong type: %v", doc["substrate_history"])
	}
}

// TestWellKnownAgentUnpublishedReturnsError checks that unpublished agents are hidden.
func TestWellKnownAgentUnpublishedReturnsError(t *testing.T) {
	agent := &domain.Agent{
		ID:        uuid.New(),
		AgentName: "hidden",
		AgentURN:  "urn:tessera:test.example.org:hidden",
		Published: false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc := buildTestService(
		newFakeAgentStore(agent),
		newFakeKeeperStore(),
		newFakeKeyStore(),
		&fakeChainStore{},
		&fakeTransitionStore{},
	)
	_, err := svc.WellKnownAgent(context.Background(), "hidden")
	if err == nil {
		t.Fatal("expected error for unpublished agent, got nil")
	}
}

// TestSvcVouchAgentAppendsChainEntry verifies vouch increments count and uses correct entry type.
func TestSvcVouchAgentAppendsChainEntry(t *testing.T) {
	agentID := uuid.New()
	agent := &domain.Agent{
		ID:        agentID,
		AgentName: "vouchme",
		AgentURN:  "urn:tessera:test.example.org:vouchme",
		Published: true,
		TrustTier: domain.TrustSelfAttested,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	agentStore := newFakeAgentStore(agent)
	svc := buildTestService(
		agentStore,
		newFakeKeeperStore(),
		newFakeKeyStore(),
		&fakeChainStore{},
		&fakeTransitionStore{},
	)

	result, err := svc.SvcVouchAgent(context.Background(), "vouchme", SvcVouchInput{
		Voucher:   "urn:tessera:test.example.org:voucher",
		Statement: "I know this agent.",
	})
	if err != nil {
		t.Fatalf("SvcVouchAgent: %v", err)
	}
	if result.VouchCount != 1 {
		t.Errorf("vouch_count: want 1, got %d", result.VouchCount)
	}
	// One vouch should not trigger tier upgrade.
	if result.TierUpgraded {
		t.Error("unexpected tier upgrade on first vouch")
	}
	if result.TrustTier != domain.TrustSelfAttested {
		t.Errorf("trust_tier: want self_attested, got %s", result.TrustTier)
	}
}

// TestSvcVouchAgentTierUpgradeAtThreshold verifies tier upgrades to community_attested at threshold.
func TestSvcVouchAgentTierUpgradeAtThreshold(t *testing.T) {
	agentID := uuid.New()
	agent := &domain.Agent{
		ID:         agentID,
		AgentName:  "threshold-agent",
		AgentURN:   "urn:tessera:test.example.org:threshold-agent",
		Published:  true,
		TrustTier:  domain.TrustSelfAttested,
		VouchCount: vouchThreshold - 1, // one vouch away from threshold
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	agentStore := newFakeAgentStore(agent)
	svc := buildTestService(
		agentStore,
		newFakeKeeperStore(),
		newFakeKeyStore(),
		&fakeChainStore{},
		&fakeTransitionStore{},
	)

	result, err := svc.SvcVouchAgent(context.Background(), "threshold-agent", SvcVouchInput{
		Voucher: "urn:tessera:test.example.org:final-voucher",
	})
	if err != nil {
		t.Fatalf("SvcVouchAgent: %v", err)
	}
	if !result.TierUpgraded {
		t.Error("expected tier upgrade at threshold, got false")
	}
	if result.TrustTier != domain.TrustCommunityAttested {
		t.Errorf("trust_tier after threshold: want community_attested, got %s", result.TrustTier)
	}
}

// TestSvcVouchAgentRequiresVoucher verifies empty voucher is rejected.
func TestSvcVouchAgentRequiresVoucher(t *testing.T) {
	agent := &domain.Agent{
		ID: uuid.New(), AgentName: "test", AgentURN: "urn:tessera:x:test",
		Published: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	svc := buildTestService(
		newFakeAgentStore(agent),
		newFakeKeeperStore(), newFakeKeyStore(),
		&fakeChainStore{}, &fakeTransitionStore{},
	)
	_, err := svc.SvcVouchAgent(context.Background(), "test", SvcVouchInput{Voucher: ""})
	if err == nil {
		t.Fatal("expected error for empty voucher, got nil")
	}
}
