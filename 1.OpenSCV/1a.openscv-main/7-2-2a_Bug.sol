pragma solidity 0.4.25;
//Dependency on External State Data
contract Game {
      address questionSender;
      string public question;
      bytes32 responseHash;

      function Try(string _response) external 
      payable{
           require(msg.sender == tx.origin);
           if (responseHash==keccak256(_response) && msg.value> 1 ether)
                { msg.sender.transfer(this.balance); }
             }    
    
     function StartGame(string _question, string _response) public
     payable {
     if (responseHash==0x0) {
        responseHash = keccak256 (_response);
        question = _question;
        questionSender = msg.sender;
     }
   }  
}