## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol
### Dependence on predictable environment variable
- SWC ID: 120 in Contract `GuessTheRandomNumberChallenge`
- Function name: `recover()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol:26
```
block.number > commitBlock + 20 && commitBlock+20 > block.number - 256
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `GuessTheRandomNumberChallenge`
- Function name: `recover()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol:26
```
block.number - 256
```
### Dependence on predictable environment variable
- SWC ID: 120 in Contract `GuessTheRandomNumberChallenge`
- Function name: `recover()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol:26
```
require(block.number > commitBlock + 20 && commitBlock+20 > block.number - 256)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol

## Dependence on predictable environment variable
- SWC ID: 120
- Severity: Low
- Contract: GuessTheRandomNumberChallenge
- Function name: `recover()`
- PC address: 368
- Estimated Gas Usage: 991 - 1086

#### Description

A control flow decision is made based on The block.number environment variable.
The block.number environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol:26

#### Code

```
block.number > commitBlock + 20 && commitBlock+20 > block.number - 256
```

#### Initial State:

Account: [CREATOR], balance: 0x40001080400040001, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0xde0b6b3a7640000
Caller: [ATTACKER], function: recover(), txdata: 0xce746024, value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: GuessTheRandomNumberChallenge
- Function name: `recover()`
- PC address: 374
- Estimated Gas Usage: 16947 - 77702

#### Description

The arithmetic operator can underflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol:26

#### Code

```
block.number - 256
```

#### Initial State:

Account: [CREATOR], balance: 0x2001400042040010, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0xde0b6b3a7640000
Caller: [SOMEGUY], function: guess(uint8), txdata: 0x4ba4c16b, value: 0xde0b6b3a7640000


## Dependence on predictable environment variable
- SWC ID: 120
- Severity: Low
- Contract: GuessTheRandomNumberChallenge
- Function name: `recover()`
- PC address: 388
- Estimated Gas Usage: 1011 - 1106

#### Description

A control flow decision is made based on The block.number environment variable.
The block.number environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Fixed/4-1a_Fixed.sol:26

#### Code

```
require(block.number > commitBlock + 20 && commitBlock+20 > block.number - 256)
```

#### Initial State:

Account: [CREATOR], balance: 0x2001080440040001, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0xde0b6b3a7640000
Caller: [ATTACKER], function: recover(), txdata: 0xce746024, value: 0x0


