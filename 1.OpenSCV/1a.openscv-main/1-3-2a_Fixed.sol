pragma solidity 0.8.0;
//Improper Exception Handling of External Calls
contract Provider {
    function isCustomer(address _customer) public returns (bool) {}
}


contract ProviderExample {
    function getService(address provider, address customer) public {
        if (this.contractExists(provider) == false) {
            // Handle the situation (review, or message, etc.)
        }
        Provider r = Provider(provider);

        if (r.isCustomer(customer)) {
            //providing service
        }
    }


function contractExists(address c) public  view returns (bool) {
    uint size;
    assembly {
        size := extcodesize(c)
    }
    return size > 0;
}
}
