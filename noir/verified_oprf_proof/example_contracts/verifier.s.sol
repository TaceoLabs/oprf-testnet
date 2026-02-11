// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Note: This is an example script showing how to verify a proof using a deployed HonkVerifier contract.

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../verifier.sol";

contract HonkVerifierScript is Script {
    HonkVerifier public verifier;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        verifier = new HonkVerifier();
        vm.stopBroadcast();
        console.log("HonkVerifier deployed to:", address(verifier));
    }
}
