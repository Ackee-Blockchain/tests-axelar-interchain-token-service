// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

import "contracts/utils/ERC20Permit.sol";

contract ERC20PermitMock is ERC20Permit {
    string public name;
    string public symbol;
    uint8 public decimals;
    address public owner;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        owner = msg.sender;
        _setDomainTypeSignatureHash(name);
    }

    function mint(address account, uint256 amount) external {
        require(msg.sender == owner, "ERC20PermitMock: minting not allowed");
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) external {
        require(msg.sender == owner, "ERC20PermitMock: burning not allowed");
        _burn(account, amount);
    }
}