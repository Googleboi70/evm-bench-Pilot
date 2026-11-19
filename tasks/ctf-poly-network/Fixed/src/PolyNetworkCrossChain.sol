// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CrossChainManager + CrossChainData
/// @notice Minimal reproduction of the real Poly Network EthCrossChainManager/EthCrossChainData
///         contracts exploited on Ethereum mainnet, 2021-08-11 (~$611M across ETH/BSC/Polygon,
///         the largest DeFi hack at the time; nearly all funds were later voluntarily returned
///         by the attacker).
///
/// @dev REAL PROTOCOL CONTEXT
///      Poly Network's `EthCrossChainManager` is a privileged relay: it verifies a source-chain
///      block header (via consensus-node signatures) and a Merkle proof that a specific
///      cross-chain transaction was included in that block, then calls
///      `executeCrossChainTx`, which invokes the DESTINATION-side target contract named inside
///      the proven message. This reproduction keeps that real function name
///      (`verifyHeaderAndExecuteTx`) and its real consequence (an arbitrary external call to a
///      caller-named target using caller-named calldata) while replacing the actual BLS/multi-
///      signature consensus-header verification and Merkle-inclusion proof with a stand-in
///      `_verifyProof` -- that machinery is extensive and genuinely sound in the real protocol;
///      it is NOT where the bug lived, so reproducing it in full would only obscure the actual
///      vulnerability.
///
///      Per the real post-mortem: "Poly checks that the target is a contract, but they forgot
///      to prevent users from calling [Poly's own] EthCrossChainData contract... tricking
///      EthCrossChainManager into calling EthCrossChainData, passing the onlyOwner check"
///      (because `msg.sender` for that internal call IS EthCrossChainManager itself, which
///      genuinely is EthCrossChainData's configured owner) "...to trigger the function that
///      changes the public keys" -- i.e. the consensus key Poly itself trusts to verify ALL
///      FUTURE cross-chain messages. This reproduction implements that exact chain: the manager
///      never excludes its own trusted config contract from the set of callable targets.
contract CrossChainData {
    address public owner;
    bytes public currentEpochConsensusPubKey;

    event ConsensusKeyChanged(bytes newKey);

    constructor(address _owner) {
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// @dev Standard ownership transfer, used once during deployment wiring to hand control to
    ///      the CrossChainManager (see the constructor-cycle note in the test's setUp()).
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /// @notice Sets the consensus public key that ALL future cross-chain header verifications
    ///         will trust. Correctly restricted to `owner` -- which, in the real deployment (and
    ///         this reproduction), is the CrossChainManager contract itself.
    function putCurEpochConPubKeyBytes(bytes calldata newKey) external onlyOwner returns (bool) {
        currentEpochConsensusPubKey = newKey;
        emit ConsensusKeyChanged(newKey);
        return true;
    }

    function getCurEpochConPubKeyBytes() external view returns (bytes memory) {
        return currentEpochConsensusPubKey;
    }
}

contract CrossChainManager {
    CrossChainData public immutable dataContract;

    constructor(CrossChainData _dataContract) {
        dataContract = _dataContract;
    }

    /// @notice Normal flow: a genuinely proven cross-chain message calls a DeFi-side contract
    ///         (e.g. a lock/release proxy) to release funds to the message's named recipient.
    ///
    /// @dev THE REAL VULNERABLE LOGIC (1:1 with the incident): `toContract` is read directly
    ///      from the (proven) message and called with no restriction on which address it may
    ///      be -- including the manager's OWN `dataContract`. Since `msg.sender` during that
    ///      call is this manager contract, and this manager IS `dataContract.owner()`, ANY
    ///      function gated by `onlyOwner` on `dataContract` becomes reachable through a
    ///      sufficiently crafted cross-chain message.
    function verifyHeaderAndExecuteTx(address toContract, bytes calldata method, bytes calldata args, bytes calldata proof)
        external
        returns (bool)
    {
        require(_verifyProof(proof), "invalid header/merkle proof");

        // =====================================================================================
        // VULNERABLE: no `require(toContract != address(dataContract))` (or, more generally, no
        // allowlist of legitimate destination-side targets) anywhere before this call.
        // =====================================================================================
        require(toContract != address(dataContract), "invalid target");
        (bool ok,) = toContract.call(abi.encodePacked(bytes4(keccak256(bytes(method))), args));
        require(ok, "cross-chain execution failed");
        return true;
    }

    /// @dev Stand-in for Poly's real consensus-signature + Merkle-inclusion verification. That
    ///      machinery is not the vulnerability -- this simplification exists so the challenge
    ///      can focus entirely on the actual bug (the unrestricted `toContract.call` above).
    function _verifyProof(bytes calldata proof) internal pure returns (bool) {
        return proof.length > 0;
    }
}
