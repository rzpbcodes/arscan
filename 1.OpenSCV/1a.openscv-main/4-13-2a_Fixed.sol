pragma solidity 0.5.0;
//Write to Arbitrary Storage Location
contract Wallet {
    uint[] private bonusCodes;
    address private owner;
    //[several lines of code]
    function PushBonusCode(uint c) public {
        bonusCodes.push(c); }
    function PopBonusCode() public {
        require(0 < bonusCodes.length);
        bonusCodes.length--;}
    function UpdateBonusCodeAt(uint idx, uint c) public {
        require(idx < bonusCodes.length);
        bonusCodes[idx] = c;}
}