pragma solidity 0.4.25;
//Improper locking during external calls
contract bid {
    // several lines of code
    uint state;
    mapping(address => uint) public pendingReturns;

    constructor() public {
        state = 0; // new/finalized
    }

    function withdraw(uint highestBid, address highestBidder) public {
        require(state == 0); // Only State Finalized
        // State change
        state = 1; //States.InTransition ;
        // Actions
        uint amount = pendingReturns[msg.sender];
        if (amount > 0) {
            if (msg.sender != highestBidder) msg.sender.transfer(amount);
            else msg.sender.transfer(amount - highestBid);
            pendingReturns[msg.sender] = 0;
        }
        // State change
        state = 0;
    }
}
