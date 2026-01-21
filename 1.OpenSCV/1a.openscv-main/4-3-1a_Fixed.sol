pragma solidity 0.4.24;
//Missing Check On Transfer Credit
contract SimpleBank {
    mapping(address => uint) bal;

    function withdraw() {
        bool b = msg.sender.send(bal[msg.sender]);
        if (b) bal[msg.sender] = 0;
    }
}
