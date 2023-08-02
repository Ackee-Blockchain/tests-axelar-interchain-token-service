// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

import "contracts/interfaces/IInterchainTokenExecutable.sol";

contract PayloadReceiver is IInterchainTokenExecutable {
    bytes public lastPayload;

    function exectuteWithInterchainToken(
        string calldata sourceChain,
        bytes calldata sourceAddress,
        // to mimic executeWithToken more maybe?
        bytes calldata data,
        bytes32 tokenId,
        uint256 amount
    ) external {
        lastPayload = data;
    }
}