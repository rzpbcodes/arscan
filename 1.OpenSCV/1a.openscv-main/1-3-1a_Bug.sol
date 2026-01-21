pragma solidity 0.8.0;
//Improper Check of External Call Return Value
contract Item 

{
function addProduct() external returns (bool) {

 // [several lines of code] 

 }
}

contract ContractERP {
  
  function newPurchaseOrder(Item product) public {
     product.addProduct();
     // [several lines of code] 
  }
}


