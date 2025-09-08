## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Fixed/1-3-2a_Fixed.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `ProviderExample`
- Function name: `getService(address,address)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Fixed/1-3-2a_Fixed.sol:15
```
r.isCustomer(customer)
```
### Multiple Calls in a Single Transaction
- SWC ID: 113 in Contract `ProviderExample`
- Function name: `getService(address,address)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Fixed/1-3-2a_Fixed.sol:15
```
r.isCustomer(customer)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Fixed/1-3-2a_Fixed.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: ProviderExample
- Function name: `getService(address,address)`
- PC address: 388
- Estimated Gas Usage: 4777 - 74186

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Fixed/1-3-2a_Fixed.sol:15

#### Code

```
r.isCustomer(customer)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: getService(address,address), txdata: 0xa10bd97a000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000000000000000000101010101010101010101010101010200000000, decoded_data: ('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', '0x0101010101010101010101010101010200000000'), value: 0x0


## Multiple Calls in a Single Transaction
- SWC ID: 113
- Severity: Low
- Contract: ProviderExample
- Function name: `getService(address,address)`
- PC address: 388
- Estimated Gas Usage: 4777 - 74186

#### Description

Multiple calls are executed in the same transaction.
This call is executed following another call within the same transaction. It is possible that the call never gets executed if a prior call fails permanently. This might be caused intentionally by a malicious callee. If possible, refactor the code such that each transaction only executes one external call or make sure that all callees can be trusted (i.e. they’re part of your own codebase).
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-2a_Fixed/1-3-2a_Fixed.sol:15

#### Code

```
r.isCustomer(customer)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: getService(address,address), txdata: 0xa10bd97a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010101010101050101010101010200000000, decoded_data: ('0x0000000000000000000000000000000000000000', '0x0101010101010101050101010101010200000000'), value: 0x0


