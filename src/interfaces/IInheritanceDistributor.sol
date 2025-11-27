//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;

/**
 * @title IInheritanceDistributor
 * @notice Interface for asset distribution
 */
interface IInheritanceDistributor {
    event InheritanceDistributed(
        uint256 indexed willId,
        address indexed heir,
        bytes32 dataCID
    );

    function distributeInheritance(
        uint256 willId,
        bytes calldata mpcSignature,
        string[] calldata heirDataCIDs
    ) external;
}
