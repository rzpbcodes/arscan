
pragma solidity 0.4.25;
//Missing variable initialization
contract Uninitialized{
    address  destination = msg.sender;

    function transfer() payable public{
        destination.transfer(msg.value);
    }
}
