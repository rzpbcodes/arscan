## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `UnusedVariables`
- Function name: `unusedArg(int256,int256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol:8
```
x + a
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `UnusedVariables`
- Function name: `tupleAssignment(int256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol:13
```
y - x
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `UnusedVariables`
- Function name: `unusedReturn(int256,int256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol:13
```
y - x
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol

## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: UnusedVariables
- Function name: `unusedArg(int256,int256)`
- PC address: 495
- Estimated Gas Usage: 1146 - 1522

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol:8

#### Code

```
x + a
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: unusedArg(int256,int256), txdata: 0x2e591df5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, decoded_data: (-1, -1), value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: UnusedVariables
- Function name: `tupleAssignment(int256)`
- PC address: 555
- Estimated Gas Usage: 434 - 905

#### Description

The arithmetic operator can underflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol:13

#### Code

```
y - x
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: tupleAssignment(int256), txdata: 0x0ee1207d0101010101010101010101010101010101010101010101010101010101010107, decoded_data: (454086624460063511464984254936031011189294057512315937409637584344757371143,), value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: UnusedVariables
- Function name: `unusedReturn(int256,int256)`
- PC address: 555
- Estimated Gas Usage: 478 - 1044

#### Description

The arithmetic operator can underflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Bug/4-7-3a_Bug.sol:13

#### Code

```
y - x
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: unusedReturn(int256,int256), txdata: 0xfb90017220408010002020800101408020800408008000808080402040044008808001012040801000002080004080002000040800000000000010200004400000800040, decoded_data: (14587973221715093153584380437203079484352379864064800056011387224701483876609, 14587973221701929117107348819571906902309735274169595318314253261067203379264), value: 0x0


