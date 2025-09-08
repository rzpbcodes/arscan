## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol
### Dependence on predictable environment variable
- SWC ID: 120 in Contract `Sales`
- Function name: `constructor`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:22
```
super.validPurchase() || (whitelist[msg.sender] && !hasEnded())
```
### Dependence on predictable environment variable
- SWC ID: 120 in Contract `Sales`
- Function name: `constructor`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:42
```
super.validPurchase() && withinCap
```
### Dependence on predictable environment variable
- SWC ID: 120 in Contract `Sales`
- Function name: `constructor`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:10
```
current >= 1000 && current <= 4000
```
### Dependence on predictable environment variable
- SWC ID: 120 in Contract `Sales`
- Function name: `constructor`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:12
```
withinPeriod && nonZeroPurchase
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol

## Dependence on predictable environment variable
- SWC ID: 120
- Severity: Low
- Contract: Sales
- Function name: `constructor`
- PC address: 84
- Estimated Gas Usage: 353 - 448

#### Description

A control flow decision is made based on The block.number environment variable.
The block.number environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:22

#### Code

```
super.validPurchase() || (whitelist[msg.sender] && !hasEnded())
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0


## Dependence on predictable environment variable
- SWC ID: 120
- Severity: Low
- Contract: Sales
- Function name: `constructor`
- PC address: 248
- Estimated Gas Usage: 314 - 409

#### Description

A control flow decision is made based on The block.number environment variable.
The block.number environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:42

#### Code

```
super.validPurchase() && withinCap
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0


## Dependence on predictable environment variable
- SWC ID: 120
- Severity: Low
- Contract: Sales
- Function name: `constructor`
- PC address: 293
- Estimated Gas Usage: 226 - 321

#### Description

A control flow decision is made based on The block.number environment variable.
The block.number environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:10

#### Code

```
current >= 1000 && current <= 4000
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0


## Dependence on predictable environment variable
- SWC ID: 120
- Severity: Low
- Contract: Sales
- Function name: `constructor`
- PC address: 317
- Estimated Gas Usage: 270 - 365

#### Description

A control flow decision is made based on The block.number environment variable.
The block.number environment variable is used to determine a control flow decision. Note that the values of variables like coinbase, gaslimit, block number and timestamp are predictable and can be manipulated by a malicious miner. Also keep in mind that attackers know hashes of earlier blocks. Don't use any of those environment variables as sources of randomness and be aware that use of these variables introduces a certain level of trust into miners.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-5a_Bug/4-5a_Bug.sol:12

#### Code

```
withinPeriod && nonZeroPurchase
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0


