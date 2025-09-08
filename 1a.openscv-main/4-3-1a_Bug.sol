pragma solidity 0.4.24;
//Missing Check On Transfer Credit
contract SimpleBank {
    mapping(address => uint) balances;

    function withdraw() {
        msg.sender.send(balances[msg.sender]);
        balances[msg.sender] = 0;
    }
}
