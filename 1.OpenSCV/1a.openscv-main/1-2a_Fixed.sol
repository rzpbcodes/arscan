pragma solidity ^0.4.0;
//Malicious Fallback Function
contract RegisterUser 
{
   // [several lines of code]
function setNewUser()  external returns (bool) {
  // [several lines of code] 
   }
function () external payable  {
  // new id is created to control the erros
}
}

contract callExternalExample {
  function callRegisterUser(RegisterUser a) public returns (bool) {
     // calling a non-existing function
      bool success;
      success = a.setNewUser();
      return success;
      }
}

