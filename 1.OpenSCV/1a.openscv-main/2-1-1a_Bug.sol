pragma solidity 0.4.25;
//Improper Use of Exception Handling Functions
contract Vulnerable {
   function withdraw(uint256 amount) external {
   // This forwards 2300 gas, which may not be enough if the recipient
   // is a contract and gas costs change.
    msg.sender.transfer(amount);
    }
  // [several lines of code]
}