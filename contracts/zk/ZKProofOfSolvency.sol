// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ZKProofOfSolvency is Ownable, ReentrancyGuard {
    address public snarkVerifier;
    bytes32 public latestLiabilitiesRoot;
    bytes32 public latestAssetsCommitment;
    uint256 public lastUpdateTimestamp;

    event SolvencyProved(uint256 indexed timestamp, bytes32 indexed liabilitiesRoot, bytes32 assetsCommitment);

    constructor(address _snarkVerifier) Ownable(msg.sender) {
        snarkVerifier = _snarkVerifier;
    }

    function submitProofOfSolvency(
        bytes32 liabilitiesRoot,
        bytes32 assetsCommitment,
        bytes calldata zkProof
    ) external onlyOwner nonReentrant {
        uint256[] memory publicInputs = new uint256[](2);
        publicInputs[0] = uint256(liabilitiesRoot);
        publicInputs[1] = uint256(assetsCommitment);

        (bool success, bytes memory data) = snarkVerifier.call(
            abi.encodeWithSignature("verifyProof(bytes,uint256[])", zkProof, publicInputs)
        );
        require(success && abi.decode(data, (bool)), "ZKSolvency: Invalid Solvency Proof");

        latestLiabilitiesRoot = liabilitiesRoot;
        latestAssetsCommitment = assetsCommitment;
        lastUpdateTimestamp = block.timestamp;

        emit SolvencyProved(block.timestamp, liabilitiesRoot, assetsCommitment);
    }
}
