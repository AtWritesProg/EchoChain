// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

/**
 * @title IWillRegistry
 * @notice Core interface for will management
 */
interface IWillRegistry {
    enum WillState {
        Setup,
        Active,
        Warning,
        Triggered,
        Distributing,
        Distributed,
        Cancelled
    }

    event WillCreated(
        uint256 indexed willId,
        address indexed owner,
        uint256 heartbeatInterval,
        uint256 gracePeriod
    );

    event StateTransitioned(
        uint256 indexed willId,
        WillState indexed fromState,
        WillState indexed toState,
        uint256 timestamp
    );

    function createWill(
        uint256 heartbeatInterval,
        uint256 gracePeriod,
        address[] calldata heirs,
        uint256[] calldata heirShares,
        uint256 heirThreshold,
        bytes32 zkCommitment,
        bytes32 dataRootHash,
        string calldata ipfsCID
    ) external returns (uint256);

    function getWillState(uint256 willId) external view returns (WillState);
}
