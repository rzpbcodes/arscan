pragma solidity ^0.8.0;
//Stack-based Buffer Overflow
contract StackDepthTest {
    constructor() {}

    function a2() internal {
        // [Several lines of code]
    }

    function a() internal {
        a();
    }

    function b() external {
        a();
    }
}
