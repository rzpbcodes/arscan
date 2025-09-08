pragma solidity ^0.4.0;
//Wrong Function Call
// This is our interface (note that it's not really a full
// contract, just a specification of available functions).
contract Reservable {
    function reserve(uint seats) payable {}
}

contract FoodBudgetWallet {
   address constant private _restaurant = 0xE0f5206BBD039e7b0592d8918820024e2a7437C9;
    
    function FoodBudgetWallet(address _restaurant) {
       //   [several lines of code]
    }
    
    function makeReservation(uint seats) {
        Reservable r = Reservable(_restaurant);
        r.reserve.value(1 ether)(seats);
    }
    
    function() payable {}
}