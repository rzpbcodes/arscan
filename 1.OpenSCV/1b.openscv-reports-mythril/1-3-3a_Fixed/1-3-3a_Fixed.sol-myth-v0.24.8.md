## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-3a_Fixed/1-3-3a_Fixed.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `ReturnValue`
- Function name: `callchecked(address)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-3a_Fixed/1-3-3a_Fixed.sol:6
```
callee.call()
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-3a_Fixed/1-3-3a_Fixed.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: ReturnValue
- Function name: `callchecked(address)`
- PC address: 172
- Estimated Gas Usage: 971 - 35252

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-3a_Fixed/1-3-3a_Fixed.sol:6

#### Code

```
callee.call()
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: callchecked(address), txdata: 0x7536185edededededededededededededeadbeefdeadbeefdeadbeefdeadbeefdeadbeef, value: 0x0


