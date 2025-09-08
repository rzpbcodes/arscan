pragma solidity 0.4.25;
//Improper locking during external calls
contract bid {
    mapping(address => uint) public pendingReturns;
    //[several lines of code]
    function withdraw(uint highestBid, address highestBidder) public { 
    uint amount = pendingReturns[msg.sender];
    if ( amount > 0) {
         if (msg.sender!=highestBidder )
              msg.sender.transfer(amount);
        else
              msg.sender.transfer(amount-highestBid);
    pendingReturns[msg.sender] = 0;} 
} }