pragma solidity 0.4.25;
//Use of Same Variable or Function Name In Inherited Contract
contract Tokensale {
    uint hardcap = 10000 ether;
    function Tokensale() {}
    function fetchCap() public constant returns(uint) {
        return hardcap;}
}

contract Presale is Tokensale {
    uint hardcap = 1000 ether;
    function Presale() Tokensale() {}
}