// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;
//Wrong Function Modifier
// This will report a warning
contract C {
    bytes x = "012345678901234567890123456789";

    function test() public returns(uint) {
        x.push() =0x01;
        x.push() = 0x02;
        return x.length;
    }
}