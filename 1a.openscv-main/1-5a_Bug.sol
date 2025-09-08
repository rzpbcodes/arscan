// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.4.25;
//Interoperability issues with other contracts
contract Constant{
    uint counter;
    function myFunction() public view returns(uint){
       counter = counter +1;
       return counter;
    }
}
pragma solidity >=0.5.0 <0.9.0;
contract NewContract {
    function doSomething(address _addr) public returns (bool) {
          _addr.call(abi.encodeWithSignature("myFunction()"));
         // [several lines of code]
}
}

