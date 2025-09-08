pragma solidity 0.4.25;

contract Fixed {
     function withdraw(uint256 amount) external {
     // This forwards all available gas. Be sure to check the return value!
     bool success;
      success = msg.sender.call.value(amount)('100');
      require(success, 'Transfer failed.');
     }
  //[several lines of code]
}