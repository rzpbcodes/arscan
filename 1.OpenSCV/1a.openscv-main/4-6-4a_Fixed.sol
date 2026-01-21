pragma solidity 0.4.25;
//Missing type in variable declaration
contract TestLooping {
    function looping() internal{
        for (uint32 i = 0; i <= 256; i++) {
            //do something
        }
    }
}
