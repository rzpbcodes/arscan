## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `UnusedVariables`
- Function name: `unusedArg(int256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol:7
```
x + a
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `UnusedVariables`
- Function name: `tupleAssignment(int256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol:12
```
y - x
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `UnusedVariables`
- Function name: `unusedReturn(int256,int256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol:12
```
y - x
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol

## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: UnusedVariables
- Function name: `unusedArg(int256)`
- PC address: 521
- Estimated Gas Usage: 1139 - 1515

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol:7

#### Code

```
x + a
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: unusedArg(int256), txdata: 0xd70c1672ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, decoded_data: (-1,), value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: UnusedVariables
- Function name: `tupleAssignment(int256)`
- PC address: 536
- Estimated Gas Usage: 434 - 905

#### Description

The arithmetic operator can underflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol:12

#### Code

```
y - x
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: tupleAssignment(int256), txdata: 0x0ee1207d0101010101010101010101010101010101010101010101010101010101010105, decoded_data: (454086624460063511464984254936031011189294057512315937409637584344757371141,), value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: UnusedVariables
- Function name: `unusedReturn(int256,int256)`
- PC address: 536
- Estimated Gas Usage: 478 - 1044

#### Description

The arithmetic operator can underflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-7-3a_Fixed/4-7-3a_Fixed.sol:12

#### Code

```
y - x
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: unusedReturn(int256,int256), txdata: 0xfb90017280408008104020804080028000100880201001808080800880800080a08480098040800410402080400000000000008020080080000000088080000080048008, decoded_data: (-57782082765588941618640222423649789176555521524020011162003698104879743205367, -57782082873428728287255042502006182036100284147893369319037280233227781111800), value: 0x0


