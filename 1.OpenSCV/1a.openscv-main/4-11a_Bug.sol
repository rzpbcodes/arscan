//Starting from Solidity 0.4.0, contracts without the fallback function will reject payment by default. This makes the function in Listing 11 redundant.
//function () external payable{ revert () ;
//}
pragma solidity 0.5.0;
//Redundant Functionality
contract ExRedundant
{
   
   function() external payable
   { 
    revert();
   } 

}