// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Counter} from "../src/Counter.sol";

contract DeployCounter is Script {
    function run() external returns (Counter) {
        vm.startBroadcast();

        Counter counter = new Counter();

        console.log("Counter deployed to:", address(counter));
        console.log("Owner:", counter.owner());

        vm.stopBroadcast();

        return counter;
    }
}
