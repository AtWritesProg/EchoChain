//SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/**
 * @title CryptoLib
 * @notice Library for cryptographic operations
 */
library CryptoLib {
    /**
     * @notice Verify ECDSA signature
     * @dev Wrapper around ecrecover with proper error handling
     */
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        if (signature.length != 65) {
            return false;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) {
            return false;
        }

        address recovered = ecrecover(messageHash, v, r, s);
        return recovered != address(0) && recovered == expectedSigner;
    }

    /**
     * @notice Compute EIP-712 typed data hash
     */
    function getTypedDataHash(
        bytes32 domainSeparator,
        bytes32 structHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19\x01", domainSeparator, structHash)
            );
    }
}
