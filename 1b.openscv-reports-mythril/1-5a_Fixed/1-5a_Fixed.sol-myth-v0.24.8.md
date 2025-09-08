## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-5a_Fixed/1-5a_Fixed.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `NewContract`
- Function name: `doSomething(address)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-5a_Fixed/1-5a_Fixed.sol:16
```
_addr.call(abi.encodeWithSignature("myFunction()"))
```
### Unchecked return value from external call.
- SWC ID: 104 in Contract `NewContract`
- Function name: `doSomething(address)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-5a_Fixed/1-5a_Fixed.sol:16
```
_addr.call(abi.encodeWithSignature("myFunction()"))
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-5a_Fixed/1-5a_Fixed.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: NewContract
- Function name: `doSomething(address)`
- PC address: 435
- Estimated Gas Usage: 1433 - 37546

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-5a_Fixed/1-5a_Fixed.sol:16

#### Code

```
_addr.call(abi.encodeWithSignature("myFunction()"))
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: doSomething(address), txdata: 0xe60c2d44dededededededededededededeadbeefdeadbeefdeadbeefdeadbeefdeadbeef, value: 0x0


## Unchecked return value from external call.
- SWC ID: 104
- Severity: Medium
- Contract: NewContract
- Function name: `doSomething(address)`
- PC address: 435
- Estimated Gas Usage: 1433 - 37546

#### Description

The return value of a message call is not checked.
External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller. The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-5a_Fixed/1-5a_Fixed.sol:16

#### Code

```
_addr.call(abi.encodeWithSignature("myFunction()"))
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: doSomething(address), txdata: 0xe60c2d444444444444444444444444444444444444444444444444444444444444444444, value: 0x0
Caller: [ATTACKER], function: doSomething(address), txdata: 0xe60c2d444444444444444444444444444444444444444444444444444444444444444444, value: 0x0


