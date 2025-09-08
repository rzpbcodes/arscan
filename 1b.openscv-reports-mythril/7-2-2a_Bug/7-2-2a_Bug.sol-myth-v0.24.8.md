## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `Game`
- Function name: `StartGame(string,string)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:15
```
function StartGame(string _question, string _response) public
     payable {
     if (responseHash==0x0) {
        responseHash = keccak256 (_response);
        question = _question;
        questionSender = msg.sender;
     }
   }
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `Game`
- Function name: `StartGame(string,string)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:15
```
function StartGame(string _question, string _response) public
     payable {
     if (responseHash==0x0) {
        responseHash = keccak256 (_response);
        question = _question;
        questionSender = msg.sender;
     }
   }
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `Game`
- Function name: `Try(string)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:8
```
function Try(string _response) external 
      payable{
           require(msg.sender == tx.origin);
           if (responseHash==keccak256(_response) && msg.value> 1 ether)
                { msg.sender.transfer(this.balance); }
             }
```
### Dependence on tx.origin
- SWC ID: 115 in Contract `Game`
- Function name: `Try(string)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:10
```
require(msg.sender == tx.origin)
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `Game`
- Function name: `StartGame(string,string)`
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol

## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: Game
- Function name: `StartGame(string,string)`
- PC address: 119
- Estimated Gas Usage: 18837 - 85983

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:15

#### Code

```
function StartGame(string _question, string _response) public
     payable {
     if (responseHash==0x0) {
        responseHash = keccak256 (_response);
        question = _question;
        questionSender = msg.sender;
     }
   }
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x40000000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: StartGame(string,string), txdata: 0x1f1c827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdce1, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: Game
- Function name: `StartGame(string,string)`
- PC address: 140
- Estimated Gas Usage: 18870 - 85923

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:15

#### Code

```
function StartGame(string _question, string _response) public
     payable {
     if (responseHash==0x0) {
        responseHash = keccak256 (_response);
        question = _question;
        questionSender = msg.sender;
     }
   }
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x1, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: StartGame(string,string), txdata: 0x1f1c827ff43bb4000000000000000000000000000000000000000000000000001d588000da, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: Game
- Function name: `Try(string)`
- PC address: 281
- Estimated Gas Usage: 1277 - 3862

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:8

#### Code

```
function Try(string _response) external 
      payable{
           require(msg.sender == tx.origin);
           if (responseHash==keccak256(_response) && msg.value> 1 ether)
                { msg.sender.transfer(this.balance); }
             }
```

#### Initial State:

Account: [CREATOR], balance: 0x1, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: Try(string), txdata: 0x3853682cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc, value: 0x0


## Dependence on tx.origin
- SWC ID: 115
- Severity: Low
- Contract: Game
- Function name: `Try(string)`
- PC address: 716
- Estimated Gas Usage: 245 - 340

#### Description

Use of tx.origin as a part of authorization control.
The tx.origin environment variable has been found to influence a control flow decision. Note that using tx.origin as a security control might cause a situation where a user inadvertently authorizes a smart contract to perform an action on their behalf. It is recommended to use msg.sender instead.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-2a_Bug/7-2-2a_Bug.sol:10

#### Code

```
require(msg.sender == tx.origin)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: Try(string), txdata: 0x3853682c, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: Low
- Contract: Game
- Function name: `StartGame(string,string)`
- PC address: 1111
- Estimated Gas Usage: 18870 - 85923

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.  This issue is reported for internal compiler generated code.

#### Initial State:

Account: [CREATOR], balance: 0x1, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: StartGame(string,string), txdata: 0x1f1c827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbaff, value: 0x0


