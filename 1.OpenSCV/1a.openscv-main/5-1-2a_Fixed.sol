pragma solidity ^0.5.0;
//Incorrect Function Call Order

contract EthTxOrderDependenceMinimal {
    address payable public owner;
    uint public reward;

    constructor() public{
        owner = msg.sender;
    }

   
    function claimReward(uint256 submission) public payable{
        require(submission < 10);
        require(msg.sender == owner);
        reward = msg.value;
        msg.sender.transfer(reward);

    }
}

