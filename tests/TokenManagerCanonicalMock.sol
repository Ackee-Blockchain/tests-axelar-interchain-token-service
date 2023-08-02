// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

import "contracts/tokenManager/implementations/TokenManagerCanonical.sol";
import "contracts/interfaces/IERC20BurnableMintable.sol";

contract TokenManagerCanonicalMock is TokenManagerCanonical, IERC20BurnableMintable {
    using AddressBytesUtils for bytes;

    constructor(address interchainTokenService_)
        TokenManagerCanonical(interchainTokenService_) {
    }

    function mint(address account, uint256 amount) external {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) external {
        _burn(account, amount);
    }
}