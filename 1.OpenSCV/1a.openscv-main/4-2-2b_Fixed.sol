pragma solidity 0.5.0;
//Wrong Constructor
contract Foo{
     address public owner ; //owner is the owner of the contrac t
    //Anyone cal now be the owner of the contract because the
    //function name is misspelled .
  constructor()  public {
   owner = msg.sender ;
}
}