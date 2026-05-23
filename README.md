# GoH
```markdown
# GoH (Guardian of Heritage)

EIP-7702 Delegation Smart Contract dengan Multi-Signature Security.

## Fitur Utama

- Multi-Signature 2-of-3 untuk perubahan kritis
- Timelock 48 jam untuk admin changes
- Atomic batch processing (all-or-nothing)
- Token whitelist (optional)
- cal3 callback untuk cross-contract interaction

## Deployment

### Prerequisites

- Foundry / Hardhat
- Solidity ^0.8.20
- Network dengan dukungan EIP-7702

### Deploy menggunakan Foundry

```bash
forge create --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  src/GoH.sol:GoH \
  --constructor-args "[0xGuardian1,0xGuardian2,0xGuardian3]"
```

EIP-7702 Delegation (Client Side)

Menggunakan Viem

```typescript
import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const userEOA = privateKeyToAccount('0xUSER_PRIVATE_KEY');
const GOH_CONTRACT = '0x...';

const client = createWalletClient({
  account: userEOA,
  chain: mainnet,
  transport: http()
});

// Sign authorization untuk delegasi
const authorization = await client.signAuthorization({
  account: userEOA,
  contractAddress: GOH_CONTRACT,
});

// Aktifkan delegasi
const hash = await client.sendTransaction({
  authorizationList: [authorization],
  to: userEOA.address,
});
```

Menggunakan cal3

```solidity
// Dari contract lain
bytes memory data = abi.encodeWithSelector(
  GoH.processPayment.selector,
  address(0),    // token (0 = ETH)
  1 ether,       // amount
  recipient      // penerima
);

bytes memory result = goh.cal3(data);
```

Multi-Signature Flow

```bash
# 1. Guardian propose perubahan
cast send $GOH "proposeAddAdmin(address)" 0xNewAdmin --private-key $GUARDIAN_1

# 2. Guardian lain vote (via proposal)
cast send $GOH "vote(bytes32,bool)" $PROPOSAL_ID true --private-key $GUARDIAN_2

# 3. Execute setelah timelock (48 jam)
cast send $GOH "executeAddAdmin()" --private-key $GUARDIAN_1
```

Fungsi Utama

Fungsi Akses Deskripsi
cal3(bytes) Cal3Executor Callback handler
forwardAllEth() Admin Forward semua ETH ke owner
forwardERC20(address,uint256) Admin Forward token tertentu
addCal3Executor(address) Guardian Tambah executor
proposeAddAdmin(address) Guardian Proposal admin baru

Event

```solidity
event AssetForwarded(address indexed from, address indexed to, uint256 amount, string assetType, uint256 nonce);
event Cal3Executed(address indexed caller, bytes4 indexed selector, bytes returnData, uint256 nonce);
event ProposalCreated(bytes32 indexed proposalId, address indexed proposer, bytes32 targetHash, uint256 eta);
```

Security

· Multi-sig 2-of-3 untuk semua perubahan admin
· Timelock 48 jam
· ReentrancyGuard
· Rate limiting untuk batch (cooldown 5 menit)
· Maksimal batch size: 20 item

License

MIT

```
