pragma solidity 0.5.0;
//Transfer Recipient Depending on Transaction Order
contract Wallet {
 // fixed address of the wallet library
 address constant walletLibrary = 0xb794F5eA0ba39494cE839613fffBA74279579268;
 // function that receives ether
 function deposit() payable public {
    // log(msg.sender, msg.value);
 }

 // function for withdrawing ether
 function withdraw() public {
     walletLibrary.delegatecall(msg.data);
 }

 // ...
} 