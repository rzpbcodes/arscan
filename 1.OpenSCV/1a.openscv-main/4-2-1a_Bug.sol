pragma solidity 0.4.25;
//Missing Constructor
contract Missing{

 address private owner;



 modifier onlyowner {

 require(msg.sender==owner);
 _;
 }

 

  function () payable {} 



function withdraw()

public

onlyowner

{

owner.transfer(this.balance);

}

}