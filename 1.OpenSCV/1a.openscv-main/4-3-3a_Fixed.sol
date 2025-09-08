pragma solidity 0.4.24;
//Wrong use of Transfer Credit Function
contract auctionFixed {
    address highestBidder;
    uint highestBid;
    mapping(address => uint) refunds;
    function bid() payable external {
        require(msg.value >= highestBid);
        if (highestBidder != 0) {
            refunds[highestBidder] += highestBid; // record the refund that this user can claim
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
       function withdrawRefund() external {
        uint refund = refunds[msg.sender];
        refunds[msg.sender] = 0;
        msg.sender.transfer(refund);
    } }