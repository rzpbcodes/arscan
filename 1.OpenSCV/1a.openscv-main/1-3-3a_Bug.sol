pragma solidity 0.4.25;
//Improper Check of Low-Level Call Return Value
contract ReturnValue {

  function callnotchecked(address callee) public {
    callee.call();
  }
}
