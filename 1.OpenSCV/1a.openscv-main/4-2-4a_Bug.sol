pragma solidity 0.4.25;
//Uninitialized Storage Variables


contract PaySupplier {
    bool public unlocked = false;
    struct Person
    {
        string name;
    }
    //[several lines of code]
    function TransferMoney(string memory _name) public {
        Person storage newTransfer;
        newTransfer.name = _name;
        //[several lines of code]
        require(unlocked);}
}
