
pragma solidity 0.4.25;
//Incorrect Use of Event Blockchain variables for Time
contract Test{
uint time = block.timestamp;
function pay (){
if (time % 2 == 1){
msg.sender.send(100);}}}

