pragma solidity 0.4.25;
//Exposed state variables
contract Stateful
{
  bool vulnerable = false;
  
   function exploit(address attacker)
     {
        require(vulnerable);
        attacker.transfer(this.balance);
     }  
}