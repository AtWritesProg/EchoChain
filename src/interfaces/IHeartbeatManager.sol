//SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/**
 * @title IHeartbeatManager
 * @notice Interface for heartbeat verification
 */

interface IHeartbeatManager {
    event HeartbeatSubmitted(
        uint256 indexed willId,
        address indexed submitter,
        uint256 timestamp,
        bytes32 proofHash
    );

    function submitHeartbeat(
        uint256 willId,
        bytes32 zkProof,
        uint256 nonce
    ) external;

    function isHeartbeatOverdue(uint256 willId) external view returns (bool);
}
