pragma solidity 0.5.0;
//Transfer Recipient Depending on Transaction Order
contract OwnableWallet {
 address payable owner;
 // called by the constructor
 function initWallet(address payable _owner) public {
 owner = _owner; // any user can change owner
 // more setup
 }
 // function that allows the owner to withdraw ether
 function withdraw(uint _amount) public {
 if (msg.sender == owner) {
        owner.transfer(_amount);
 }
 }
 // ...
 }