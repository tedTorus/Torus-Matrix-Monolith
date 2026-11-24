// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IValidationPlugin {
    function validateSignature(bytes32 hash, bytes calldata signature) external view returns (bool);
}

contract ERC6900ModularSmartAccount is ReentrancyGuard {
    address public owner;
    mapping(address => bool) public isPluginInstalled;
    mapping(bytes4 => address) public executionPlugins;
    address public currentValidationPlugin;

    modifier onlyOwner() {
        require(msg.sender == owner || msg.sender == address(this), "Not authorized");
        _;
    }

    constructor(address _owner, address _initialValidationPlugin) {
        owner = _owner;
        currentValidationPlugin = _initialValidationPlugin;
    }

    fallback() external payable {
        address plugin = executionPlugins[msg.sig];
        require(plugin != address(0), "No plugin found");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), plugin, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}
