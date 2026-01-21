pragma solidity ^0.4.24;
//Use of the Same Variable or Function Name In a Single Contract
//Use of the Same Variable or Function Name In a Single Contract
contract Bug {
    uint owner;

    function sensitive_function(address p_owner) public {
        // ...
        require(p_owner == msg.sender);
    }

    function alternate_sensitive_function() public {
        address owner = msg.sender;
        // ...
        require(owner == msg.sender);
    }
}