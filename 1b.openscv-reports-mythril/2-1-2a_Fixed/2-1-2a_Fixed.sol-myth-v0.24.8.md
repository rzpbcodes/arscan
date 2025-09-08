## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Fixed/2-1-2a_Fixed.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `auction`
- Function name: `withdrawRefund()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Fixed/2-1-2a_Fixed.sol:22
```
msg.sender.call.value(refund)("")
```
### Transaction Order Dependence
- SWC ID: 114 in Contract `auction`
- Function name: `withdrawRefund()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Fixed/2-1-2a_Fixed.sol:22
```
msg.sender.call.value(refund)("")
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Fixed/2-1-2a_Fixed.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: auction
- Function name: `withdrawRefund()`
- PC address: 298
- Estimated Gas Usage: 6943 - 61604

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Fixed/2-1-2a_Fixed.sol:22

#### Code

```
msg.sender.call.value(refund)("")
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: withdrawRefund(), txdata: 0x110f8874, value: 0x0


## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: auction
- Function name: `withdrawRefund()`
- PC address: 298
- Estimated Gas Usage: 6943 - 61604

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Fixed/2-1-2a_Fixed.sol:22

#### Code

```
msg.sender.call.value(refund)("")
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: withdrawRefund(), txdata: 0x110f8874, value: 0x0


