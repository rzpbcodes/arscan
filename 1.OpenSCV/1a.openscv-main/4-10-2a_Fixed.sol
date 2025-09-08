//SPDX-License-Identifier: MIT
pragma solidity >0.8.0 <0.9.0;
//Missing Constant Modifier in Variable Declaration
// any contract can use it
uint constant pi=314; 

contract C1{
    uint constant FavorateNumber=25;
    function getNumbers() public pure returns(uint){
        return FavorateNumber*pi;
    }
}
contract C2{
    function getPi() public pure returns(uint){
       return pi;
    }
}