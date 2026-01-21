pragma solidity 0.4.13;
//Wrong class inheritance order

contract SalesCompl {
// several lines of code
// overriding SalesCompl#validPurchase to add extra cap logic
function validPurchase() internal constant returns (bool) {
    uint256 current = block.number;
    bool withinPeriod;
    withinPeriod = current >= 1000 && current <= 4000;
    bool nonZeroPurchase = msg.value != 0;
    return withinPeriod && nonZeroPurchase;
    }
}



contract WhitelistedBuyers is SalesCompl {
    mapping (address => bool) public whitelist;

 function validPurchase() internal constant returns (bool) {
         return super.validPurchase() || (whitelist[msg.sender] && !hasEnded());

    }

    function hasEnded() public constant returns (bool) {
    return (block.number > 4000);
  }
}
contract Utils is SalesCompl  { 
   // several lines of code
   // overriding SalesCompl#validPurchase to add extra cap logic

   function validPurchase() internal constant returns (bool) {

    uint256  cap;
   
   
    // update state
 
    bool withinCap =  msg.value <= cap;
    return super.validPurchase() && withinCap;
  }
}
contract Sales is WhitelistedBuyers, Utils {
function Sales() {
           // several lines of code;
           super.validPurchase();
           }
 }