import "contracts/utils/Create3Fixed.sol";

contract Create3 is Create3Fixed {
    function deploy(bytes calldata bytecode, bytes32 deploySalt) external returns (address deployed) {
        deployed = _create3(bytecode, deploySalt);
    }

    function getAddress(bytes32 deploySalt) external view returns (address deployed) {
        deployed = _create3Address(deploySalt);
    }
}