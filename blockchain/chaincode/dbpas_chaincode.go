// Package main implements the DBPAS chaincode for Hyperledger Fabric.
//
// This is the native Go implementation of the DPGA and TGCB protocols
// described in the DBPAS paper, for deployment on Fabric without the EVM layer.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"golang.org/x/crypto/sha3"
)

// ─── Data Structures ────────────────────────────────────────────────────────

// Product represents a registered product NFT.
type Product struct {
	PID             string `json:"pid"`
	Name            string `json:"name"`
	Metadata        string `json:"metadata"`
	Manufacturer    string `json:"manufacturer"`
	CurrentOwner    string `json:"currentOwner"`
	CheckpointCount int    `json:"checkpointCount"`
	MintTimestamp    int64  `json:"mintTimestamp"`
}

// Checkpoint represents a single DPGA checkpoint record.
type Checkpoint struct {
	Index     int    `json:"index"`
	GcLat     int64  `json:"gcLat"`     // GPS latitude × 1e6
	GcLon     int64  `json:"gcLon"`     // GPS longitude × 1e6
	GdLat     int64  `json:"gdLat"`     // destination latitude × 1e6
	GdLon     int64  `json:"gdLon"`     // destination longitude × 1e6
	Timestamp int64  `json:"timestamp"` // Unix timestamp
	Nonce     string `json:"nonce"`     // hex-encoded keccak256 nonce
	Sender    string `json:"sender"`    // sender's identity
	Receiver  string `json:"receiver"`  // receiver's identity
	Consumed  bool   `json:"consumed"`  // replay-attack flag
}

// Entity represents a registered MSP entity.
type Entity struct {
	Address string `json:"address"`
	Role    int    `json:"role"` // 0=manufacturer, 1=distributor, 2=retailer, 3=consumer
	Active  bool   `json:"active"`
}

// DBPASContract is the smart contract for the DBPAS system.
type DBPASContract struct {
	contractapi.Contract
}

// ─── Constants ──────────────────────────────────────────────────────────────

const (
	EarthRadius  = 6371000.0 // meters
	DefaultVmax  = 33.33     // m/s ≈ 120 km/h
	GPSTolerance = 50.0      // meters

	ProductPrefix    = "PRODUCT_"
	CheckpointPrefix = "CHECKPOINT_"
	NoncePrefix      = "NONCE_"
	EntityPrefix     = "ENTITY_"
	ConfigKey        = "CONFIG"
)

// Config stores system configuration on the ledger.
type Config struct {
	Vmax         float64 `json:"vmax"`
	GPSTolerance float64 `json:"gpsTolerance"`
	Admin        string  `json:"admin"`
}

// ─── Initialization ─────────────────────────────────────────────────────────

// InitLedger initializes the chaincode with default configuration.
func (c *DBPASContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %v", err)
	}

	config := Config{
		Vmax:         DefaultVmax,
		GPSTolerance: GPSTolerance,
		Admin:        clientID,
	}

	configJSON, _ := json.Marshal(config)
	if err := ctx.GetStub().PutState(ConfigKey, configJSON); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	// Register the admin as a manufacturer
	entity := Entity{
		Address: clientID,
		Role:    0,
		Active:  true,
	}
	entityJSON, _ := json.Marshal(entity)
	return ctx.GetStub().PutState(EntityPrefix+clientID, entityJSON)
}

// ─── Entity Registration ────────────────────────────────────────────────────

// RegisterEntity registers a new entity with a role.
func (c *DBPASContract) RegisterEntity(ctx contractapi.TransactionContextInterface, address string, role int) error {
	if role < 0 || role > 3 {
		return fmt.Errorf("invalid role: must be 0-3")
	}

	entity := Entity{
		Address: address,
		Role:    role,
		Active:  true,
	}

	entityJSON, _ := json.Marshal(entity)
	return ctx.GetStub().PutState(EntityPrefix+address, entityJSON)
}

// ─── Product Minting ────────────────────────────────────────────────────────

// MintProduct creates a new product NFT.
func (c *DBPASContract) MintProduct(ctx contractapi.TransactionContextInterface, pid string, name string, metadata string) error {
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get identity: %v", err)
	}

	// Verify entity is registered as manufacturer
	entity, err := c.getEntity(ctx, clientID)
	if err != nil {
		return fmt.Errorf("entity not registered: %v", err)
	}
	if entity.Role != 0 {
		return fmt.Errorf("only manufacturers can mint products")
	}

	// Check product doesn't already exist
	existing, _ := ctx.GetStub().GetState(ProductPrefix + pid)
	if existing != nil {
		return fmt.Errorf("product already exists: %s", pid)
	}

	product := Product{
		PID:             pid,
		Name:            name,
		Metadata:        metadata,
		Manufacturer:    clientID,
		CurrentOwner:    clientID,
		CheckpointCount: 0,
		MintTimestamp:    time.Now().Unix(),
	}

	productJSON, _ := json.Marshal(product)
	if err := ctx.GetStub().PutState(ProductPrefix+pid, productJSON); err != nil {
		return err
	}

	// Set initial nonce: keccak256(PID || 0)
	initialNonce := keccak256Hash([]byte(pid + "0"))
	return ctx.GetStub().PutState(NoncePrefix+pid, []byte(initialNonce))
}

// ─── DPGA Checkpoint ────────────────────────────────────────────────────────

// DPGACheckpoint records a dual-party geo-nonce attestation checkpoint.
func (c *DBPASContract) DPGACheckpoint(
	ctx contractapi.TransactionContextInterface,
	pid string,
	gcLat int64, gcLon int64,
	gdLat int64, gdLon int64,
	sigSenderHex string, sigReceiverHex string,
	senderPubKeyHex string, receiverPubKeyHex string,
	newOwner string,
) error {
	// Get product
	product, err := c.getProduct(ctx, pid)
	if err != nil {
		return err
	}

	clientID, _ := ctx.GetClientIdentity().GetID()
	if product.CurrentOwner != clientID {
		return fmt.Errorf("sender must be current owner")
	}

	// Verify receiver is registered
	_, err = c.getEntity(ctx, newOwner)
	if err != nil {
		return fmt.Errorf("receiver not registered")
	}

	// Get previous nonce
	prevNonceBytes, _ := ctx.GetStub().GetState(NoncePrefix + pid)
	prevNonce := string(prevNonceBytes)

	k := product.CheckpointCount
	timestamp := time.Now().Unix()

	// Construct message mk = keccak256(PID || k || Gc || Gd || T || N_{k-1})
	message := fmt.Sprintf("%s%d%d%d%d%d%d%s",
		pid, k, gcLat, gcLon, gdLat, gdLon, timestamp, prevNonce)
	messageHash := keccak256Hash([]byte(message))

	// Verify ECDSA signatures
	if err := verifySignature(senderPubKeyHex, messageHash, sigSenderHex); err != nil {
		return fmt.Errorf("invalid sender signature: %v", err)
	}
	if err := verifySignature(receiverPubKeyHex, messageHash, sigReceiverHex); err != nil {
		return fmt.Errorf("invalid receiver signature: %v", err)
	}

	// TGCB enforcement
	if k > 0 {
		prevCP, err := c.getCheckpoint(ctx, pid, k-1)
		if err != nil {
			return fmt.Errorf("failed to get previous checkpoint: %v", err)
		}

		distance := haversine(
			float64(prevCP.GcLat)/1e6, float64(prevCP.GcLon)/1e6,
			float64(gcLat)/1e6, float64(gcLon)/1e6,
		)

		timeDelta := float64(timestamp - prevCP.Timestamp)
		if timeDelta <= 0 {
			return fmt.Errorf("zero or negative time delta")
		}

		config, _ := c.getConfig(ctx)
		if distance > config.GPSTolerance {
			velocity := distance / timeDelta
			if velocity > config.Vmax {
				return fmt.Errorf("TGCB violation: velocity %.2f m/s exceeds max %.2f m/s", velocity, config.Vmax)
			}
		}
	}

	// Compute new nonce: Nk = keccak256(sigSender || sigReceiver)
	newNonce := keccak256Hash([]byte(sigSenderHex + sigReceiverHex))

	// Store GPS commitment (hash only, raw GPS goes to PDC)
	gpsCommitment := keccak256Hash([]byte(fmt.Sprintf("%d%d%d%d", gcLat, gcLon, gdLat, gdLon)))

	// Store checkpoint
	checkpoint := Checkpoint{
		Index:     k,
		GcLat:     gcLat,
		GcLon:     gcLon,
		GdLat:     gdLat,
		GdLon:     gdLon,
		Timestamp: timestamp,
		Nonce:     newNonce,
		Sender:    clientID,
		Receiver:  newOwner,
		Consumed:  false,
	}

	cpJSON, _ := json.Marshal(checkpoint)
	cpKey := fmt.Sprintf("%s%s_%d", CheckpointPrefix, pid, k)
	if err := ctx.GetStub().PutState(cpKey, cpJSON); err != nil {
		return err
	}

	// Store GPS commitment
	commitKey := fmt.Sprintf("GPS_COMMIT_%s_%d", pid, k)
	ctx.GetStub().PutState(commitKey, []byte(gpsCommitment))

	// Update nonce
	ctx.GetStub().PutState(NoncePrefix+pid, []byte(newNonce))

	// Update product ownership
	product.CheckpointCount = k + 1
	product.CurrentOwner = newOwner
	productJSON, _ := json.Marshal(product)
	ctx.GetStub().PutState(ProductPrefix+pid, productJSON)

	// Store raw GPS in Private Data Collection (PDC)
	gpsData := map[string]interface{}{
		"pid":   pid,
		"index": k,
		"gcLat": gcLat,
		"gcLon": gcLon,
		"gdLat": gdLat,
		"gdLon": gdLon,
	}
	gpsJSON, _ := json.Marshal(gpsData)
	transientMap, _ := ctx.GetStub().GetTransient()
	collectionName := "privateGPSCollection"
	if _, ok := transientMap["collection"]; ok {
		collectionName = string(transientMap["collection"])
	}
	ctx.GetStub().PutPrivateData(collectionName, fmt.Sprintf("GPS_%s_%d", pid, k), gpsJSON)

	return nil
}

// ─── Verification ───────────────────────────────────────────────────────────

// Verify checks product authenticity.
// Returns: "0" = authentic, "1" = clone, "2" = tampered
func (c *DBPASContract) Verify(ctx contractapi.TransactionContextInterface, pid string, nonce string) (string, error) {
	existing, _ := ctx.GetStub().GetState(ProductPrefix + pid)
	if existing == nil {
		return "2", nil // tampered — unknown product
	}

	storedNonce, _ := ctx.GetStub().GetState(NoncePrefix + pid)
	if string(storedNonce) != nonce {
		return "1", nil // clone — nonce mismatch
	}

	return "0", nil // authentic
}

// ─── Query Functions ────────────────────────────────────────────────────────

// GetProduct returns product details.
func (c *DBPASContract) GetProduct(ctx contractapi.TransactionContextInterface, pid string) (*Product, error) {
	return c.getProduct(ctx, pid)
}

// GetCheckpoint returns a specific checkpoint.
func (c *DBPASContract) GetCheckpoint(ctx contractapi.TransactionContextInterface, pid string, index int) (*Checkpoint, error) {
	return c.getCheckpoint(ctx, pid, index)
}

// GetCheckpointHistory returns all checkpoints for a product.
func (c *DBPASContract) GetCheckpointHistory(ctx contractapi.TransactionContextInterface, pid string) ([]*Checkpoint, error) {
	product, err := c.getProduct(ctx, pid)
	if err != nil {
		return nil, err
	}

	history := make([]*Checkpoint, 0, product.CheckpointCount)
	for i := 0; i < product.CheckpointCount; i++ {
		cp, err := c.getCheckpoint(ctx, pid, i)
		if err != nil {
			return nil, err
		}
		history = append(history, cp)
	}
	return history, nil
}

// GetLatestNonce returns the current nonce for a product.
func (c *DBPASContract) GetLatestNonce(ctx contractapi.TransactionContextInterface, pid string) (string, error) {
	nonce, err := ctx.GetStub().GetState(NoncePrefix + pid)
	if err != nil {
		return "", err
	}
	return string(nonce), nil
}

// ─── Helper Functions ───────────────────────────────────────────────────────

func (c *DBPASContract) getProduct(ctx contractapi.TransactionContextInterface, pid string) (*Product, error) {
	data, err := ctx.GetStub().GetState(ProductPrefix + pid)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("product not found: %s", pid)
	}
	var product Product
	json.Unmarshal(data, &product)
	return &product, nil
}

func (c *DBPASContract) getCheckpoint(ctx contractapi.TransactionContextInterface, pid string, index int) (*Checkpoint, error) {
	key := fmt.Sprintf("%s%s_%d", CheckpointPrefix, pid, index)
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("checkpoint not found: %s index %d", pid, index)
	}
	var cp Checkpoint
	json.Unmarshal(data, &cp)
	return &cp, nil
}

func (c *DBPASContract) getEntity(ctx contractapi.TransactionContextInterface, address string) (*Entity, error) {
	data, err := ctx.GetStub().GetState(EntityPrefix + address)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("entity not found: %s", address)
	}
	var entity Entity
	json.Unmarshal(data, &entity)
	return &entity, nil
}

func (c *DBPASContract) getConfig(ctx contractapi.TransactionContextInterface) (*Config, error) {
	data, _ := ctx.GetStub().GetState(ConfigKey)
	if data == nil {
		return &Config{Vmax: DefaultVmax, GPSTolerance: GPSTolerance}, nil
	}
	var config Config
	json.Unmarshal(data, &config)
	return &config, nil
}

// keccak256Hash computes keccak256 and returns hex string.
func keccak256Hash(data []byte) string {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// haversine computes great-circle distance in meters between two GPS points.
func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0

	lat1Rad := lat1 * math.Pi / 180.0
	lat2Rad := lat2 * math.Pi / 180.0

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*math.Sin(dLon/2)*math.Sin(dLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return EarthRadius * c
}

// verifySignature verifies an ECDSA signature.
func verifySignature(pubKeyHex string, messageHash string, signatureHex string) error {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %v", err)
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %v", err)
	}

	// Parse public key
	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil {
		return fmt.Errorf("failed to parse public key")
	}
	pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// Parse signature (r || s, each 32 bytes)
	if len(sigBytes) < 64 {
		return fmt.Errorf("signature too short")
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	// Hash the message
	msgBytes, _ := hex.DecodeString(messageHash)
	hash := sha256.Sum256(msgBytes)

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// ConsumeCheckpoint marks a checkpoint as consumed (replay prevention).
func (c *DBPASContract) ConsumeCheckpoint(ctx contractapi.TransactionContextInterface, pid string, index int) error {
	cp, err := c.getCheckpoint(ctx, pid, index)
	if err != nil {
		return err
	}
	if cp.Consumed {
		return fmt.Errorf("checkpoint already consumed")
	}
	cp.Consumed = true
	cpJSON, _ := json.Marshal(cp)
	key := fmt.Sprintf("%s%s_%d", CheckpointPrefix, pid, index)
	return ctx.GetStub().PutState(key, cpJSON)
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	chaincode, err := contractapi.NewChaincode(&DBPASContract{})
	if err != nil {
		fmt.Printf("Error creating DBPAS chaincode: %v\n", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting DBPAS chaincode: %v\n", err)
	}
}
