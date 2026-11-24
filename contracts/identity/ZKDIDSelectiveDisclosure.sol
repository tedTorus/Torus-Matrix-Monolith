// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ZKDIDSelectiveDisclosure is Ownable, ReentrancyGuard {
    address public snarkVerifier;
    mapping(address => bool) public trustedIssuers;
    mapping(bytes32 => bool) public usedNullifiers;

    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    event CredentialVerified(address indexed user, uint256 queryId, bytes32 nullifier);

    constructor(address _snarkVerifier) Ownable(msg.sender) {
        snarkVerifier = _snarkVerifier;
    }

    function addTrustedIssuer(address issuer) external onlyOwner {
        trustedIssuers[issuer] = true;
        emit IssuerAdded(issuer);
    }

    function verifyCredentialAndExecute(
        uint256 queryId, 
        address issuer,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant {
        require(trustedIssuers[issuer], "ZKDID: Untrusted issuer");
        require(!usedNullifiers[nullifier], "ZKDID: Proof already used");

        uint256[] memory publicInputs = new uint256[](4);
        publicInputs[0] = uint160(issuer);
        publicInputs[1] = queryId;
        publicInputs[2] = uint256(nullifier);
        publicInputs[3] = uint160(msg.sender);

        (bool success, bytes memory data) = snarkVerifier.call(
            abi.encodeWithSignature("verifyProof(bytes,uint256[])", zkProof, publicInputs)
        );
        require(success && abi.decode(data, (bool)), "ZKDID: Invalid ZK Proof");

        usedNullifiers[nullifier] = true;
        emit CredentialVerified(msg.sender, queryId, nullifier);
    }
}
