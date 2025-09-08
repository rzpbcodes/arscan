pragma solidity 0.4.24;
//Wrong use of Transfer Credit Function
contract auction {
    address highestBidder;
    uint highestBid;

    function bid() payable {
        require(msg.value >= highestBid);
        if (highestBidder != 0) {
            highestBidder.transfer(highestBid); // if this call consistently fails, no one else can bid
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
