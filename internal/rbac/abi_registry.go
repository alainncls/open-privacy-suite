package rbac

// Built-in ABI registry for standard token types. These ABIs contain the events
// and core view/mutate functions needed for event signature extraction and
// parameter validation. When a contract has no custom ABI uploaded but is known
// to be a standard token type, these built-in ABIs serve as a fallback.

// builtInABIs maps canonical token type names (uppercase) to their ABI JSON.
var builtInABIs = map[string]string{
	"ERC20":  erc20ABI,
	"ERC721": erc721ABI,
}

// GetBuiltInABI returns the built-in ABI JSON for a known token type.
// Recognized types: "ERC20", "ERC721" (case-insensitive matching not applied;
// callers should pass uppercase). Returns "" for unknown types.
func GetBuiltInABI(tokenType string) string {
	return builtInABIs[tokenType]
}

// erc20ABI is a standard ERC-20 ABI covering the Transfer and Approval events
// plus the core view and mutate functions needed for param-type validation.
const erc20ABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "spender", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Approval",
		"type": "event"
	},
	{
		"inputs": [],
		"name": "name",
		"outputs": [{"name": "", "type": "string"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "symbol",
		"outputs": [{"name": "", "type": "string"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "decimals",
		"outputs": [{"name": "", "type": "uint8"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "totalSupply",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [{"name": "account", "type": "address"}],
		"name": "balanceOf",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "to", "type": "address"},
			{"name": "amount", "type": "uint256"}
		],
		"name": "transfer",
		"outputs": [{"name": "", "type": "bool"}],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "spender", "type": "address"},
			{"name": "amount", "type": "uint256"}
		],
		"name": "approve",
		"outputs": [{"name": "", "type": "bool"}],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "owner", "type": "address"},
			{"name": "spender", "type": "address"}
		],
		"name": "allowance",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	}
]`

// erc721ABI is a standard ERC-721 ABI covering Transfer, Approval, and
// ApprovalForAll events.
const erc721ABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": true, "name": "tokenId", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "approved", "type": "address"},
			{"indexed": true, "name": "tokenId", "type": "uint256"}
		],
		"name": "Approval",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "operator", "type": "address"},
			{"indexed": false, "name": "approved", "type": "bool"}
		],
		"name": "ApprovalForAll",
		"type": "event"
	},
	{
		"inputs": [{"name": "tokenId", "type": "uint256"}],
		"name": "ownerOf",
		"outputs": [{"name": "", "type": "address"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [{"name": "owner", "type": "address"}],
		"name": "balanceOf",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "from", "type": "address"},
			{"name": "to", "type": "address"},
			{"name": "tokenId", "type": "uint256"}
		],
		"name": "transferFrom",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "to", "type": "address"},
			{"name": "tokenId", "type": "uint256"}
		],
		"name": "approve",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "operator", "type": "address"},
			{"name": "approved", "type": "bool"}
		],
		"name": "setApprovalForAll",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [{"name": "tokenId", "type": "uint256"}],
		"name": "getApproved",
		"outputs": [{"name": "", "type": "address"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "owner", "type": "address"},
			{"name": "operator", "type": "address"}
		],
		"name": "isApprovedForAll",
		"outputs": [{"name": "", "type": "bool"}],
		"stateMutability": "view",
		"type": "function"
	}
]`
