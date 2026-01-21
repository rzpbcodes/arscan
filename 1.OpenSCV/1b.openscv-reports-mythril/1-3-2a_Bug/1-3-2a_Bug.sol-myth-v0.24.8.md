## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Bug/1-3-2a_Bug.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `ProviderExample`
- Function name: `getService(address,address)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Bug/1-3-2a_Bug.sol:23
```
r.isCustomer (customer)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Bug/1-3-2a_Bug.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: ProviderExample
- Function name: `getService(address,address)`
- PC address: 167
- Estimated Gas Usage: 2711 - 37463

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Bug/1-3-2a_Bug.sol:23

#### Code

```
r.isCustomer (customer)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: getService(address,address), txdata: 0xa10bd97a000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000000000000000000101010101010101010101210101010200000000, decoded_data: ('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', '0x0101010101010101010101210101010200000000'), value: 0x0


