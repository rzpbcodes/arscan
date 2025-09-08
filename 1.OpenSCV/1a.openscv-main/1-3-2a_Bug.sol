pragma solidity 0.8.0;
//Improper Exception Handling of External Calls
contract Provider
{
    function isCustomer(address _customer) public returns (bool) 
    {

    }
    
}

contract ProviderExample /// @notice Explain to an end user what this does
/// @dev Explain to a developer any extra details
/// @param Documents a parameter just like in doxygen (must be followed by parameter name)
{



function getService (address provider , address customer ) public {
Provider r = Provider (provider) ;


if ( r.isCustomer (customer) ) {
//providing service
}
}
}