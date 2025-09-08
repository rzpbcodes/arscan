pragma solidity ^0.4.18;
//Transfer Amount Depending on Transaction Order
contract AmountSender {

 uint public amount = 1;
 //[several lines of code]


function setAmountOp2(uint _amount) public 
{
    if ( isProvider(msg.sender))
       amount = _amount;
}

function setAmountOp1(uint _amount) public 
{
    if ( isRecipient(msg.sender))
         amount = _amount;
}

function  isProvider(address sender) public returns (bool)
 {
     //[several lines of code]
     return true;
 }

function  isRecipient(address sender) public returns (bool)
 {
     //[several lines of code]
     return true;
 }

 function setTransferAmount(uint _amount) public { 
       msg.sender.transfer(amount);} 

} 