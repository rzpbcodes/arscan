## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-1a_Fixed/4-3-1a_Fixed.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `SimpleBank`
- Function name: `withdraw()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-1a_Fixed/4-3-1a_Fixed.sol:7
```
msg.sender.send(bal[msg.sender])
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-1a_Fixed/4-3-1a_Fixed.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: SimpleBank
- Function name: `withdraw()`
- PC address: 205
- Estimated Gas Usage: 6936 - 61597

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-1a_Fixed/4-3-1a_Fixed.sol:7

#### Code

```
msg.sender.send(bal[msg.sender])
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: withdraw(), txdata: 0x3ccfd60b, value: 0x0


