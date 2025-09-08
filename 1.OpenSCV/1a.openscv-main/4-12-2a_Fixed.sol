pragma solidity ^0.4.24;
//Variables or Functions Named After Reserved Words
contract Bug {
    uint agora; 

    function assertAgora(bool condition) public {
        // Overshadows built-in symbol for providing assertions.
    }

    function get_next_expiration(uint earlier_time) private returns (uint) {
        return agora + 259200;
    }
}