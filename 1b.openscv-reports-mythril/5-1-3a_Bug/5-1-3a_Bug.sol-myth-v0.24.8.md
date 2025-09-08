## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol
### Dependence on predictable environment variable
- SWC ID: 116 in Contract `Lock`
- Function name: `fallback`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:23
```
case 0 { revert(0, 0) }
```
### Dependence on predictable environment variable
- SWC ID: 116 in Contract `Lock`
- Function name: `fallback`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:24
```
case 1 {
                switch call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
                case 0 { revert(0, 0) }
            }
```
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `Lock`
- Function name: `fallback`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:25
```
call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
```
### Transaction Order Dependence
- SWC ID: 114 in Contract `Lock`
- Function name: `fallback`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:25
```
call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `Lock`
- Function name: `fallback`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:25
```
call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
```
### Integer Arithmetic Bugs
- SWC ID: 101 in Contract `Lockdrop`
- Function name: `constructor`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:48
```
startTime + LOCK_DROP_PERIOD
```
### Dependence on predictable environment variable
- SWC ID: 116 in Contract `Lockdrop`
- Function name: `signal(address,uint32,bytes)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:100
```
require(now >= LOCK_START_TIME)
```
### Dependence on predictable environment variable
- SWC ID: 116 in Contract `Lockdrop`
- Function name: `signal(address,uint32,bytes)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:108
```
require(now <= LOCK_END_TIME)
```
### Dependence on predictable environment variable
- SWC ID: 116 in Contract `Lockdrop`
- Function name: `lock(uint8,bytes,bool)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:100
```
require(now >= LOCK_START_TIME)
```
### Dependence on predictable environment variable
- SWC ID: 116 in Contract `Lockdrop`
- Function name: `lock(uint8,bytes,bool)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:108
```
require(now <= LOCK_END_TIME)
```
### Exception State
- SWC ID: 110 in Contract `Lockdrop`
- Function name: `lock(uint8,bytes,bool)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:65
```
unlockTimeForTerm(term)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol

## Dependence on predictable environment variable
- SWC ID: 116
- Severity: Low
- Contract: Lock
- Function name: `fallback`
- PC address: 16
- Estimated Gas Usage: 838 - 933

#### Description

A control flow decision is made based on The block.timestamp environment variable.
The block.timestamp environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:23

#### Code

```
case 0 { revert(0, 0) }
```

#### Initial State:

Account: [CREATOR], balance: 0x100000010000001, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: unknown, txdata: 0x, decoded_data: , value: 0x0


## Dependence on predictable environment variable
- SWC ID: 116
- Severity: Low
- Contract: Lock
- Function name: `fallback`
- PC address: 23
- Estimated Gas Usage: 860 - 955

#### Description

A control flow decision is made based on The block.timestamp environment variable.
The block.timestamp environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:24

#### Code

```
case 1 {
                switch call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
                case 0 { revert(0, 0) }
            }
```

#### Initial State:

Account: [CREATOR], balance: 0x2, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: unknown, txdata: 0x, decoded_data: , value: 0x0


## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: Lock
- Function name: `fallback`
- PC address: 45
- Estimated Gas Usage: 3129 - 37224

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:25

#### Code

```
call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
```

#### Initial State:

Account: [CREATOR], balance: 0x400, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: 000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef, decoded_data: , value: 0x0
Caller: [CREATOR], function: unknown, txdata: 0x, decoded_data: , value: 0x0


## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: Lock
- Function name: `fallback`
- PC address: 45
- Estimated Gas Usage: 3129 - 37224

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:25

#### Code

```
call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
```

#### Initial State:

Account: [CREATOR], balance: 0x1, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x1, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: unknown, txdata: 0x, decoded_data: , value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: Lock
- Function name: `fallback`
- PC address: 45
- Estimated Gas Usage: 3129 - 37224

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:25

#### Code

```
call(gas, sload(0x00), balance(address), 0, 0, 0, 0)
```

#### Initial State:

Account: [CREATOR], balance: 0x48080000101000000, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x210661a107ec86000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: 000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef, decoded_data: , value: 0x0
Caller: [SOMEGUY], function: unknown, txdata: 0x, decoded_data: , value: 0x0
Caller: [ATTACKER], function: unknown, txdata: 0x, decoded_data: , value: 0x0


## Integer Arithmetic Bugs
- SWC ID: 101
- Severity: High
- Contract: Lockdrop
- Function name: `constructor`
- PC address: 78
- Estimated Gas Usage: 10696 - 55680

#### Description

The arithmetic operator can overflow.
It is possible to cause an integer overflow or underflow in the arithmetic operation.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:48

#### Code

```
startTime + LOCK_DROP_PERIOD
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc6, decoded_data: , value: 0x0


## Dependence on predictable environment variable
- SWC ID: 116
- Severity: Low
- Contract: Lockdrop
- Function name: `signal(address,uint32,bytes)`
- PC address: 3646
- Estimated Gas Usage: 1329 - 1424

#### Description

A control flow decision is made based on The block.timestamp environment variable.
The block.timestamp environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:100

#### Code

```
require(now >= LOCK_START_TIME)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: signal(address,uint32,bytes), txdata: 0x911fab44000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, value: 0x0


## Dependence on predictable environment variable
- SWC ID: 116
- Severity: Low
- Contract: Lockdrop
- Function name: `signal(address,uint32,bytes)`
- PC address: 3663
- Estimated Gas Usage: 2160 - 2255

#### Description

A control flow decision is made based on The block.timestamp environment variable.
The block.timestamp environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:108

#### Code

```
require(now <= LOCK_END_TIME)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: signal(address,uint32,bytes), txdata: 0x911fab44000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, value: 0x0


## Dependence on predictable environment variable
- SWC ID: 116
- Severity: Low
- Contract: Lockdrop
- Function name: `lock(uint8,bytes,bool)`
- PC address: 4077
- Estimated Gas Usage: 1327 - 1422

#### Description

A control flow decision is made based on The block.timestamp environment variable.
The block.timestamp environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:100

#### Code

```
require(now >= LOCK_START_TIME)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x1, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: lock(uint8,bytes,bool), txdata: 0xa40d30600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000000, value: 0x0


## Dependence on predictable environment variable
- SWC ID: 116
- Severity: Low
- Contract: Lockdrop
- Function name: `lock(uint8,bytes,bool)`
- PC address: 4094
- Estimated Gas Usage: 2158 - 2253

#### Description

A control flow decision is made based on The block.timestamp environment variable.
The block.timestamp environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:108

#### Code

```
require(now <= LOCK_END_TIME)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x2, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: lock(uint8,bytes,bool), txdata: 0xa40d30600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b0000000000000000000000000000000000000000000000000000000000000000, value: 0x0


## Exception State
- SWC ID: 110
- Severity: Medium
- Contract: Lockdrop
- Function name: `lock(uint8,bytes,bool)`
- PC address: 4521
- Estimated Gas Usage: 2270 - 2365

#### Description

An assertion violation was triggered.
It is possible to trigger an assertion violation. Note that Solidity assert() statements should only be used to check invariants. Review the transaction trace generated for this issue and either make sure your program logic is correct, or use require() instead of assert() if your goal is to constrain user inputs or enforce preconditions. Remember to validate inputs from both callers (for instance, via passed arguments) and callees (for instance, via return values).
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-3a_Bug/5-1-3a_Bug.sol:65

#### Code

```
unlockTimeForTerm(term)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: lock(uint8,bytes,bool), txdata: 0xa40d3060000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, value: 0x0


