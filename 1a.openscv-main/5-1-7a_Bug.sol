pragma solidity 0.4.25;
//Exposed state variables
contract Stateful
{
  bool vulnerable = false;
  function makeVulnerable() public
    {
       vulnerable = true;
    }
  
   function exploit(address attacker) internal
     {
        require(vulnerable);
        attacker.transfer(this.balance);
     }  
}