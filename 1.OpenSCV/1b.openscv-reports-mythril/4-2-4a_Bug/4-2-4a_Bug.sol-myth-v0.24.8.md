## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-4a_Bug/4-2-4a_Bug.sol
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `PaySupplier`
- Function name: `TransferMoney(string)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-4a_Bug/4-2-4a_Bug.sol:12
```
function TransferMoney(string memory _name) public {
        Person storage newTransfer;
        newTransfer.name = _name;
        //[several lines of code]
        require(unlocked);}
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `PaySupplier`
- Function name: `TransferMoney(string)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-4a_Bug/4-2-4a_Bug.sol:12
```
function TransferMoney(string memory _name) public {
        Person storage newTransfer;
        newTransfer.name = _name;
        //[several lines of code]
        require(unlocked);}
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `PaySupplier`
- Function name: `TransferMoney(string)`
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `PaySupplier`
- Function name: `TransferMoney(string)`
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `PaySupplier`
- Function name: `TransferMoney(string)`
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-4a_Bug/4-2-4a_Bug.sol

## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: PaySupplier
- Function name: `TransferMoney(string)`
- PC address: 168
- Estimated Gas Usage: 17595 - 80981

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-4a_Bug/4-2-4a_Bug.sol:12

#### Code

```
function TransferMoney(string memory _name) public {
        Person storage newTransfer;
        newTransfer.name = _name;
        //[several lines of code]
        require(unlocked);}
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: TransferMoney(string), txdata: 0x6b750beaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: PaySupplier
- Function name: `TransferMoney(string)`
- PC address: 189
- Estimated Gas Usage: 7455 - 30655

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-4a_Bug/4-2-4a_Bug.sol:12

#### Code

```
function TransferMoney(string memory _name) public {
        Person storage newTransfer;
        newTransfer.name = _name;
        //[several lines of code]
        require(unlocked);}
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: TransferMoney(string), txdata: 0x6b750beac1, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: Low
- Contract: PaySupplier
- Function name: `TransferMoney(string)`
- PC address: 323
- Estimated Gas Usage: 12512 - 55712

#### Description

The arithmetic operator can underflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.  This issue is reported for internal compiler generated code.

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: TransferMoney(string), txdata: 0x6b750beac7, value: 0x0
Caller: [CREATOR], function: TransferMoney(string), txdata: 0x6b750beae5, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: Low
- Contract: PaySupplier
- Function name: `TransferMoney(string)`
- PC address: 376
- Estimated Gas Usage: 7455 - 30655

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.  This issue is reported for internal compiler generated code.

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: TransferMoney(string), txdata: 0x6b750beaff, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: Low
- Contract: PaySupplier
- Function name: `TransferMoney(string)`
- PC address: 390
- Estimated Gas Usage: 7455 - 30655

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.  This issue is reported for internal compiler generated code.

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: TransferMoney(string), txdata: 0x6b750bea8b, value: 0x0


