pragma solidity 0.4.18; 

contract Vault {
bytes32 private password ;
function Vault ( bytes32 _password ) public payable 
{
  password = _password ;
}

  //Miners can take all the money of the contract
function unlock (address _owner , bytes32 _password) public{
if (password == _password ) {
    _owner.transfer (this.balance);
}
}
}