package siwe

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func validateDomain(domain *string) (bool, error) {
	if isEmpty(domain) {
		return false, &InvalidMessage{"`domain` must not be empty"}
	}

	urlString := *domain
	if !strings.HasPrefix(urlString, "http://") && !strings.HasPrefix(urlString, "https://") {
		urlString = fmt.Sprintf("https://%s", *domain)
	}
	_, err := url.Parse(urlString)
	if err != nil {
		return false, &InvalidMessage{"Invalid format for field `domain`"}
	}

	return true, nil
}

func validateURI(uri *string) (*url.URL, error) {
	if isEmpty(uri) {
		return nil, &InvalidMessage{"`uri` must not be empty"}
	}

	validateURI, err := url.Parse(*uri)
	if err != nil {
		return nil, &InvalidMessage{"Invalid format for field `uri`"}
	}

	return validateURI, nil
}

// InitMessage creates a Message object with the provided parameters
func InitMessage(domain, address, uri, nonce string, options map[string]interface{}) (*Message, error) {
	if ok, err := validateDomain(&domain); !ok {
		return nil, err
	}

	if isEmpty(&address) {
		return nil, &InvalidMessage{"`address` must not be empty"}
	}

	validateURI, err := validateURI(&uri)
	if err != nil {
		return nil, err
	}

	if isEmpty(&nonce) {
		return nil, &InvalidMessage{"`nonce` must not be empty"}
	}

	var statement *string
	if val, ok := options["statement"]; ok {
		value := val.(string)
		statement = &value
	}

	var chainId int
	if val, ok := options["chainId"]; ok {
		switch val.(type) {
		case float64:
			chainId = int(val.(float64))
		case int:
			chainId = val.(int)
		case string:
			parsed, err := strconv.Atoi(val.(string))
			if err != nil {
				return nil, &InvalidMessage{"Invalid format for field `chainId`, must be an integer"}
			}
			chainId = parsed
		default:
			return nil, &InvalidMessage{"`chainId` must be a string or a integer"}
		}
	} else {
		chainId = 1
	}

	var issuedAt string
	timestamp, err := parseTimestamp(options, "issuedAt")
	if err != nil {
		return nil, err
	}

	if timestamp != nil {
		issuedAt = *timestamp
	} else {
		issuedAt = time.Now().UTC().Format(time.RFC3339)
	}

	var expirationTime *string
	timestamp, err = parseTimestamp(options, "expirationTime")
	if err != nil {
		return nil, err
	}

	if timestamp != nil {
		expirationTime = timestamp
	}

	var notBefore *string
	timestamp, err = parseTimestamp(options, "notBefore")
	if err != nil {
		return nil, err
	}

	if timestamp != nil {
		notBefore = timestamp
	}

	var requestID *string
	if val, ok := isStringAndNotEmpty(options, "requestId"); ok {
		requestID = val
	}

	var resources []url.URL
	if val, ok := options["resources"]; ok {
		switch val.(type) {
		case []url.URL:
			resources = val.([]url.URL)
		default:
			return nil, &InvalidMessage{"`resources` must be a []url.URL"}
		}
	}

	return &Message{
		domain:  domain,
		address: common.HexToAddress(address),
		uri:     *validateURI,
		version: "1",

		statement: statement,
		nonce:     nonce,
		chainID:   chainId,

		issuedAt:       issuedAt,
		expirationTime: expirationTime,
		notBefore:      notBefore,

		requestID: requestID,
		resources: resources,
	}, nil
}

func parseMessage(message string) (map[string]interface{}, error) {
	match := _SIWE_MESSAGE.FindStringSubmatch(message)

	if match == nil {
		return nil, &InvalidMessage{"Message could not be parsed"}
	}

	result := make(map[string]interface{})
	for i, name := range _SIWE_MESSAGE.SubexpNames() {
		if i != 0 && name != "" && match[i] != "" {
			result[name] = match[i]
		}
	}

	if _, ok := result["domain"]; !ok {
		return nil, &InvalidMessage{"`domain` must not be empty"}
	}
	domain := result["domain"].(string)
	if ok, err := validateDomain(&domain); !ok {
		return nil, err
	}

	if _, ok := result["uri"]; !ok {
		return nil, &InvalidMessage{"`domain` must not be empty"}
	}
	uri := result["uri"].(string)
	if _, err := validateURI(&uri); err != nil {
		return nil, err
	}

	originalAddress := result["address"].(string)
	parsedAddress := common.HexToAddress(originalAddress)
	if originalAddress != parsedAddress.String() {
		return nil, &InvalidMessage{"Address must be in EIP-55 format"}
	}

	if val, ok := result["resources"]; ok {
		resources := strings.Split(val.(string), "\n- ")[1:]
		validateResources := make([]url.URL, len(resources))
		for i, resource := range resources {
			validateResource, err := url.Parse(resource)
			if err != nil {
				return nil, &InvalidMessage{fmt.Sprintf("Invalid format for field `resources` at position %d", i)}
			}
			validateResources[i] = *validateResource
		}
		result["resources"] = validateResources
	}

	return result, nil
}

// ParseMessage returns a Message object by parsing an EIP-4361 formatted string
func ParseMessage(message string) (*Message, error) {
	result, err := parseMessage(message)
	if err != nil {
		return nil, err
	}

	parsed, err := InitMessage(
		result["domain"].(string),
		result["address"].(string),
		result["uri"].(string),
		result["nonce"].(string),
		result,
	)

	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func (m *Message) eip191Hash() common.Hash {
	// Ref: https://stackoverflow.com/questions/49085737/geth-ecrecover-invalid-signature-recovery-id
	data := []byte(m.String())
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

// ValidNow validates the time constraints of the message at current time.
func (m *Message) ValidNow() (bool, error) {
	return m.ValidAt(time.Now().UTC())
}

// ValidAt validates the time constraints of the message at a specific point in time.
func (m *Message) ValidAt(when time.Time) (bool, error) {
	if m.expirationTime != nil {
		if when.After(*m.getExpirationTime()) {
			return false, &ExpiredMessage{"Message expired"}
		}
	}

	if m.notBefore != nil {
		if when.Before(*m.getNotBefore()) {
			return false, &InvalidMessage{"Message not yet valid"}
		}
	}

	return true, nil
}

const isOwnerABI = `[{
    "inputs": [
        {"internalType": "address","name": "owner","type": "address"}
    ],
    "name": "isOwner",
    "outputs": [
        {"internalType": "bool","name": "","type": "bool"}
    ],
    "stateMutability": "view",
    "type": "function"
}]`

func (m *Message) VerifyERC1271Signature(
	client *ethclient.Client,
	signature string,
) (*ecdsa.PublicKey, error) {
	if isEmpty(&signature) {
		return nil, &InvalidSignature{"Signature cannot be empty"}
	}

	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return nil, &InvalidSignature{"Failed to decode signature"}
	}

	// Fix V value
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}
	if sigBytes[64] != 0 && sigBytes[64] != 1 {
		return nil, &InvalidSignature{"Invalid signature recovery byte"}
	}

	/*pkey, err := crypto.SigToPub(m.eip191Hash().Bytes(), sigBytes)
	if err != nil {
		return nil, &InvalidSignature{"Failed to recover public key from signature"}
	}

	recoveredAddress := crypto.PubkeyToAddress(*pkey)*/
	recoveredAddressBytes, err := RecoverPublicKey(m.eip191Hash().Bytes(), sigBytes)
	recoveredAddress := common.BytesToAddress(recoveredAddressBytes)

	// Pack the ERC-1271 call data
	parsed, err := abi.JSON(strings.NewReader(isOwnerABI))
	if err != nil {
		return nil, err
	}

	// Call isValidSignature on the contract
	data, err := parsed.Pack("isOwner", recoveredAddress)
	if err != nil {
		return nil, err
	}

	// Execute the contract call with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.CallContract(ctx, ethereum.CallMsg{
		To:   &m.address,
		Data: data,
	}, nil)
	if err != nil {
		return nil, err
	}

	// Unpack the result
	var isOwner bool
	err = parsed.UnpackIntoInterface(&isOwner, "isOwner", result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack result: %v", err)
	}

	if !isOwner {
		return nil, fmt.Errorf("signature verification failed: not an owner")
	}

	return nil, nil
}

// VerifyEIP191 validates the integrity of the object by matching it's signature.
func (m *Message) VerifyEIP191(signature string) (*ecdsa.PublicKey, error) {
	if isEmpty(&signature) {
		return nil, &InvalidSignature{"Signature cannot be empty"}
	}

	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return nil, &InvalidSignature{"Failed to decode signature"}
	}

	// Ref:https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	sigBytes[64] %= 27
	if sigBytes[64] != 0 && sigBytes[64] != 1 {
		return nil, &InvalidSignature{"Invalid signature recovery byte"}
	}

	pkey, err := crypto.SigToPub(m.eip191Hash().Bytes(), sigBytes)
	if err != nil {
		return nil, &InvalidSignature{"Failed to recover public key from signature"}
	}

	address := crypto.PubkeyToAddress(*pkey)

	if address != m.address {
		return nil, &InvalidSignature{"Signer address must match message address"}
	}

	return pkey, nil
}

// Verify validates time constraints and integrity of the object by matching it's signature.
func (m *Message) Verify(signature string, domain *string, nonce *string, timestamp *time.Time) (*ecdsa.PublicKey, error) {
	var err error

	if timestamp != nil {
		_, err = m.ValidAt(*timestamp)
	} else {
		_, err = m.ValidNow()
	}

	if err != nil {
		return nil, err
	}

	if domain != nil {
		if m.GetDomain() != *domain {
			return nil, &InvalidSignature{"Message domain doesn't match"}
		}
	}

	if nonce != nil {
		if m.GetNonce() != *nonce {
			return nil, &InvalidSignature{"Message nonce doesn't match"}
		}
	}

	return m.VerifyEIP191(signature)
}

func (m *Message) prepareMessage() string {
	greeting := fmt.Sprintf("%s wants you to sign in with your Ethereum account:", m.domain)
	headerArr := []string{greeting, m.address.String()}

	if isEmpty(m.statement) {
		headerArr = append(headerArr, "\n")
	} else {
		headerArr = append(headerArr, fmt.Sprintf("\n%s\n", *m.statement))
	}

	header := strings.Join(headerArr, "\n")

	uri := fmt.Sprintf("URI: %s", m.uri.String())
	version := fmt.Sprintf("Version: %s", m.version)
	chainId := fmt.Sprintf("Chain ID: %d", m.chainID)
	nonce := fmt.Sprintf("Nonce: %s", m.nonce)
	issuedAt := fmt.Sprintf("Issued At: %s", m.issuedAt)

	bodyArr := []string{uri, version, chainId, nonce, issuedAt}

	if !isEmpty(m.expirationTime) {
		value := fmt.Sprintf("Expiration Time: %s", *m.expirationTime)
		bodyArr = append(bodyArr, value)
	}

	if !isEmpty(m.notBefore) {
		value := fmt.Sprintf("Not Before: %s", *m.notBefore)
		bodyArr = append(bodyArr, value)
	}

	if !isEmpty(m.requestID) {
		value := fmt.Sprintf("Request ID: %s", *m.requestID)
		bodyArr = append(bodyArr, value)
	}

	if len(m.resources) > 0 {
		resourcesArr := make([]string, len(m.resources))
		for i, v := range m.resources {
			resourcesArr[i] = fmt.Sprintf("- %s", v.String())
		}

		resources := strings.Join(resourcesArr, "\n")
		value := fmt.Sprintf("Resources:\n%s", resources)

		bodyArr = append(bodyArr, value)
	}

	body := strings.Join(bodyArr, "\n")

	return strings.Join([]string{header, body}, "\n")
}

func (m *Message) String() string {
	return m.prepareMessage()
}

type Signature struct {
	R       string
	S       string
	V       *big.Int
	YParity *big.Int
}

func toRecoveryBit(v int64) int {
	if v >= 27 {
		v -= 27
	}
	if v >= 2 {
		v -= 2
	}
	return int(v)
}

func hexToBigInt(hexStr string) (*big.Int, error) {
	if len(hexStr) >= 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}
	n := new(big.Int)
	n, ok := n.SetString(hexStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex string: %s", hexStr)
	}
	return n, nil
}

func RecoverPublicKey(hash []byte, sig interface{}) ([]byte, error) {
	var r, s *big.Int
	var v int

	switch signature := sig.(type) {
	case Signature:
		// Handle structured signature
		var err error
		r, err = hexToBigInt(signature.R)
		if err != nil {
			return nil, fmt.Errorf("invalid R value: %v", err)
		}

		s, err = hexToBigInt(signature.S)
		if err != nil {
			return nil, fmt.Errorf("invalid S value: %v", err)
		}

		// Use YParity if available, otherwise use V
		if signature.YParity != nil {
			v = toRecoveryBit(signature.YParity.Int64())
		} else if signature.V != nil {
			v = toRecoveryBit(signature.V.Int64())
		} else {
			return nil, fmt.Errorf("missing V or YParity")
		}
	case string:
		// Handle hex string signature
		if len(signature) < 132 { // 0x + 130 chars
			return nil, fmt.Errorf("invalid signature length")
		}

		sigBytes, err := hex.DecodeString(signature[2:])
		if err != nil {
			return nil, fmt.Errorf("invalid signature hex: %v", err)
		}

		r = new(big.Int).SetBytes(sigBytes[:32])
		s = new(big.Int).SetBytes(sigBytes[32:64])
		v = toRecoveryBit(int64(sigBytes[64]))
	case []byte:
		// Handle byte array signature
		if len(signature) < 65 {
			return nil, fmt.Errorf("invalid signature length")
		}

		r = new(big.Int).SetBytes(signature[:32])
		s = new(big.Int).SetBytes(signature[32:64])
		v = toRecoveryBit(int64(signature[64]))
	default:
		return nil, fmt.Errorf("unsupported signature type")
	}

	// Create signature bytes
	sigBytes := make([]byte, 65)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:64])
	sigBytes[64] = byte(v)

	// Recover the public key
	pubKey, err := crypto.Ecrecover(hash, sigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key: %v", err)
	}

	// Verify the recovery
	_, err = secp256k1.RecoverPubkey(hash, sigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to verify recovered public key: %v", err)
	}

	return pubKey, nil
}
