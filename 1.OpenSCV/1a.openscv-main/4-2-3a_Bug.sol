
pragma solidity 0.4.25;
//Missing variable initialization
contract Uninitialized{
    address  destination;

    function transfer() payable public{
        destination.transfer(msg.value);
    }
}
