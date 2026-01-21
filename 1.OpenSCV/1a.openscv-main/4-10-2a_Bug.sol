//SPDX-License-Identifier: MIT
pragma solidity >0.8.0 <0.9.0;
//Missing Constant Modifier in Variable Declaration

contract C1{
    uint  pi=314;
    uint  FavorateNumber=25;
    function getNumbers() public view returns(uint){
        return FavorateNumber*pi;
    }
}
contract C2{
    uint  pi=314;
    function getPi() public view returns(uint){
    return pi;
    }
}