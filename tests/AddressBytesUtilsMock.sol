// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

import "contracts/libraries/AddressBytesUtils.sol";

contract AddressBytesUtilsMock {
    function toAddress(bytes memory bytesAddress) external pure returns (address addr) {
        return AddressBytesUtils.toAddress(bytesAddress);
    }

    function toBytes(address addr) external pure returns (bytes memory bytesAddress) {
        assembly {
            addr := or(addr, shl(160, 0xFFFFFFFFFFFFFFFFFFFFFFFF))
        }
        return AddressBytesUtils.toBytes(addr);
    }
}