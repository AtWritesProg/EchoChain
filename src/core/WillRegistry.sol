//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;

import {IWillRegistry} from "../interfaces/IWillRegistry.sol";
import {StateLib} from "../libraries/StateLib.sol";

/**
 * @title WillRegistry
 * @notice Main registry for digital wills with dead-man switch functionality
 * @dev Implements comprehensive will creation and management
 * @author Digital Will Team
 */

abstract contract WillRegistry is IWillRegistry {
    using StateLib for StateLib.State;

    struct Will {
        address owner;
        uint32 createdAt;
        uint32 lastHeartbeat;
        uint32 heartbeatInterval;
        uint32 gracePeriod;
        StateLib.State state;
        bytes32 zkCommitment;
        bytes32 dataRootHash;
        address[] heirs;
        mapping(address => bool) isHeir;
        mapping(address => uint256) heirShare; // Basis points (10000 = 100%)
        uint8 heirThreshold;
        uint8 confirmationCount;
        uint8 requiredConfirmations;
        mapping(address => bool) guardianConfirmed;
        mapping(address => uint32) lastConfirmation;
        uint32 confirmationStartTime;
        string ipfsCID;
        uint256 nonce;
    }

    struct GlobalConfig {
        uint32 minHeartbeatInterval;
        uint32 maxHeartbeatInterval;
        uint32 minGracePeriod;
        uint32 maxGracePeriod;
        uint32 confirmationDelay;
        uint32 distributionDelay;
        bool paused;
    }

    // Storage
    mapping(uint256 => Will) public wills;
    mapping(address => uint256[]) public ownerWills;
    mapping(address => uint256[]) public heirWills;

    uint256 public willCounter;
    GlobalConfig public config;

    // Role management
    mapping(address => bool) public isAutomator;
    mapping(address => bool) public isMPCOracle;
    address public admin;

    // EIP-712 Domain Separator
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant HEARTBEAT_TYPEHASH =
        keccak256("Heartbeat(uint256 willId,uint256 nonce,uint256 timestamp)");

    // ========================================================================
    // EVENTS
    // ========================================================================

    event WillCreated(
        uint256 indexed willId,
        address indexed owner,
        uint256 heartbeatInterval,
        uint256 gracePeriod,
        uint256 heirCount
    );

    event StateTransitioned(
        uint256 indexed willId,
        StateLib.State indexed fromState,
        StateLib.State indexed toState,
        uint256 timestamp,
        string reason
    );

    event HeartbeatSubmitted(
        uint256 indexed willId,
        address indexed submitter,
        uint256 timestamp,
        bytes32 zkCommitment
    );

    event GuardianConfirmed(
        uint256 indexed willId,
        address indexed guardian,
        uint256 confirmationCount,
        uint256 required
    );

    event WillTriggered(
        uint256 indexed willId,
        uint256 timestamp,
        string reason
    );

    event InheritanceReadyForDistribution(
        uint256 indexed willId,
        address[] heirs
    );

    event InheritanceDistributed(
        uint256 indexed willId,
        address indexed heir,
        bytes32 dataCID
    );

    event EmergencyOverride(
        uint256 indexed willId,
        address indexed owner,
        uint256 timestamp
    );

    event WillCancelled(uint256 indexed willId, uint256 timestamp);

    // ========================================================================
    // MODIFIERS
    // ========================================================================

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyWillOwner(uint256 willId) {
        require(wills[willId].owner == msg.sender, "Not will owner");
        _;
    }

    modifier onlyAutomator() {
        require(isAutomator[msg.sender], "Not automator");
        _;
    }

    modifier onlyMPCOracle() {
        require(isMPCOracle[msg.sender], "Not MPC oracle");
        _;
    }

    modifier whenNotPaused() {
        require(!config.paused, "System paused");
        _;
    }

    modifier validWillState(uint256 willId, StateLib.State requiredState) {
        require(wills[willId].state == requiredState, "Invalid will state");
        _;
    }

    // ========================================================================
    // CONSTRUCTOR
    // ========================================================================

    constructor() {
        admin = msg.sender;

        //Initialize config with sensible defaults
        config = GlobalConfig({
            minHeartbeatInterval: 7 days,
            maxHeartbeatInterval: 365 days,
            minGracePeriod: 14 days,
            maxGracePeriod: 90 days,
            confirmationDelay: 48 hours,
            distributionDelay: 7 days,
            paused: false
        });

        // EIP-712 Domain Separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("DigitalWillRegistry")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ========================================================================
    // CORE FUNCTIONS
    // ========================================================================

    /**
     * @notice Create a new digital will
     * @param heartbeatInterval Seconds between required check-ins
     * @param gracePeriod Additional time after missed heartbeat before trigger
     * @param heirs Array of heir addresses
     * @param heirShares Array of shares in basis points (10000 = 100%)
     * @param heirThreshold Minimum heirs needed to decrypt (for SSS/MPC)
     * @param zkCommitment Initial zero-knowledge commitment
     * @param dataRootHash Merkle root of encrypted data
     * @param ipfsCID IPFS content identifier
     * @return willId The ID of the created will
     */
    function createWill(
        uint256 heartbeatInterval,
        uint256 gracePeriod,
        address[] calldata heirs,
        uint256[] calldata heirShares,
        uint256 heirThreshold,
        bytes32 zkCommitment,
        bytes32 dataRootHash,
        string calldata ipfsCID
    ) external whenNotPaused returns (uint256) {
        // Input validation
        require(heirs.length > 0, "No heirs specified");
        require(heirs.length == heirShares.length, "Array length mismatch");
        require(heirs.length <= 50, "Too many heirs");
        require(
            heirThreshold > 0 && heirThreshold <= heirs.length,
            "Invalid threshold"
        );
        require(
            heartbeatInterval >= config.minHeartbeatInterval &&
                heartbeatInterval <= config.maxHeartbeatInterval,
            "Invalid heartbeat interval"
        );

        require(
            gracePeriod >= config.minGracePeriod &&
                gracePeriod <= config.maxGracePeriod,
            "Invalid grace period"
        );
        require(zkCommitment != bytes32(0), "Invalid ZK commitment");
        require(dataRootHash != bytes32(0), "Invalid data root");
        require(bytes(ipfsCID).length > 0, "Invalid IPFS CID");

        // Verify shares sum to 10000 (100%)
        uint256 totalShares = 0;
        for (uint256 i = 0; i < heirShares.length; i++) {
            require(heirs[i] != address(0), "Invalid heir address");
            require(heirShares[i] > 0, "Share must be positive");
            totalShares += heirShares[i];
        }

        require(totalShares == 10000, "Shares must sum to 100%");

        // Create will
        uint256 willId = ++willCounter;
        Will storage will = wills[willId];

        will.owner = msg.sender;
        will.createdAt = uint32(block.timestamp);
        will.lastHeartbeat = uint32(block.timestamp);
        will.heartbeatInterval = uint32(heartbeatInterval);
        will.gracePeriod = uint32(gracePeriod);
        will.state = StateLib.State.Active;
        will.zkCommitment = zkCommitment;
        will.dataRootHash = dataRootHash;
        will.heirThreshold = uint8(heirThreshold);
        will.ipfsCID = ipfsCID;

        // Set heirs
        for (uint256 i = 0; i < heirs.length; i++) {
            will.heirs.push(heirs[i]);
            will.isHeir[heirs[i]] = true;
            will.heirShare[heirs[i]] = heirShares[i];
            heirWills[heirs[i]].push(willId);
        }

        // Calculate required confirmations (1/3 of heirs, min 1, max 3)
        will.requiredConfirmations = _calculateRequiredConfirmations(
            heirs.length
        );

        // Track owner's wills
        ownerWills[msg.sender].push(willId);

        emit WillCreated(
            willId,
            msg.sender,
            heartbeatInterval,
            gracePeriod,
            heirs.length
        );

        return willId;
    }

    /**
     * @notice Perform heartbear update (called by automation)
     * @param willId The will to update
     * @param action Action to perform
     */
    function performHeartbeatUpdate(
        uint256 willId,
        string calldata action
    ) external onlyAutomator whenNotPaused {
        Will storage will = wills[willId];

        if (keccak256(bytes(action)) == keccak256(bytes("warning"))) {
            require(will.state == StateLib.State.Active, "Not in active state");
            _transitionState(
                willId,
                StateLib.State.Warning,
                "Heartbeat missed"
            );
        } else if (keccak256(bytes(action)) == keccak256(bytes("trigger"))) {
            require(
                will.state == StateLib.State.Warning,
                "Not in warning state"
            );
            _transitionState(
                willId,
                StateLib.State.Triggered,
                "Grace period expired"
            );
            emit WillTriggered(willId, block.timestamp, "Grace period expired");
        } else {
            revert("Invalid action");
        }
    }
    // ========================================================================
    // INTERNAL FUNCTIONS
    // ========================================================================
    function _transitionState(
        uint256 willId,
        StateLib.State newState,
        string memory reason
    ) internal {
        Will storage will = wills[willId];
        StateLib.State oldState = will.state;

        require(
            StateLib.isValidTransition(oldState, newState),
            "Invalid state transition"
        );

        will.state = newState;

        emit StateTransitioned(
            willId,
            oldState,
            newState,
            block.timestamp,
            reason
        );
    }

    function _calculateRequiredConfirmations(
        uint256 heirCount
    ) internal pure returns (uint8) {
        // 1/3 of heirs, minimum 1, maximum 3
        uint256 required = (heirCount + 2) / 3;
        if (required == 0) required = 1;
        if (required > 3) required = 3;
        return uint8(required);
    }
}
