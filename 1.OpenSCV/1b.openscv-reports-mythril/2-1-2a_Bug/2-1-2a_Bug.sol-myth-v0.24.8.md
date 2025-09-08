## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `auction`
- Function name: `bid()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:11
```
highestBidder.call.value(highestBid)("")
```
### Transaction Order Dependence
- SWC ID: 114 in Contract `auction`
- Function name: `bid()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:11
```
highestBidder.call.value(highestBid)("")
```
### State access after external call
- SWC ID: 107 in Contract `auction`
- Function name: `bid()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:15
```
highestBidder = msg.sender
```
### State access after external call
- SWC ID: 107 in Contract `auction`
- Function name: `bid()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:15
```
highestBidder = msg.sender
```
### State access after external call
- SWC ID: 107 in Contract `auction`
- Function name: `bid()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:16
```
highestBid = msg.value
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: auction
- Function name: `bid()`
- PC address: 267
- Estimated Gas Usage: 15138 - 90409

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:11

#### Code

```
highestBidder.call.value(highestBid)("")
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x200, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0


## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: auction
- Function name: `bid()`
- PC address: 267
- Estimated Gas Usage: 15138 - 90409

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:11

#### Code

```
highestBidder.call.value(highestBid)("")
```

#### Initial State:

Account: [CREATOR], balance: 0x3, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x1, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: bid(), txdata: 0x1998aeef, value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0


## State access after external call
- SWC ID: 107
- Severity: Medium
- Contract: auction
- Function name: `bid()`
- PC address: 296
- Estimated Gas Usage: 15138 - 90409

#### Description

Read of persistent state following external call
The contract account state is accessed after an external call to a user defined address. To prevent reentrancy issues, consider accessing the state only before the call, especially if the callee is untrusted. Alternatively, a reentrancy lock can be used to prevent untrusted callees from re-entering the contract in an intermediate state.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:15

#### Code

```
highestBidder = msg.sender
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x4000000000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0


## State access after external call
- SWC ID: 107
- Severity: Medium
- Contract: auction
- Function name: `bid()`
- PC address: 349
- Estimated Gas Usage: 15138 - 90409

#### Description

Write to persistent state following external call
The contract account state is accessed after an external call to a user defined address. To prevent reentrancy issues, consider accessing the state only before the call, especially if the callee is untrusted. Alternatively, a reentrancy lock can be used to prevent untrusted callees from re-entering the contract in an intermediate state.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:15

#### Code

```
highestBidder = msg.sender
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x4000000000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0


## State access after external call
- SWC ID: 107
- Severity: Medium
- Contract: auction
- Function name: `bid()`
- PC address: 356
- Estimated Gas Usage: 15138 - 90409

#### Description

Write to persistent state following external call
The contract account state is accessed after an external call to a user defined address. To prevent reentrancy issues, consider accessing the state only before the call, especially if the callee is untrusted. Alternatively, a reentrancy lock can be used to prevent untrusted callees from re-entering the contract in an intermediate state.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-2a_Bug/2-1-2a_Bug.sol:16

#### Code

```
highestBid = msg.value
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x4000000000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0


