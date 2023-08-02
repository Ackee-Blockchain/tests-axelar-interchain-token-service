// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

import "contracts/utils/FlowLimit.sol";

contract FlowLimitMock is FlowLimit {
    function addFlowOut(uint256 flowOutAmount) external {
        _addFlowOut(flowOutAmount);
    }

    function addFlowIn(uint256 flowInAmount) external {
        _addFlowIn(flowInAmount);
    }

    function setFlowLimit(uint256 flowLimit) external {
        _setFlowLimit(flowLimit);
    }
}