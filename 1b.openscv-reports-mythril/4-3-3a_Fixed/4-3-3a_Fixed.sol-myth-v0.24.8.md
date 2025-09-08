## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Fixed/4-3-3a_Fixed.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `auctionFixed`
- Function name: `withdrawRefund()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Fixed/4-3-3a_Fixed.sol:18
```
msg.sender.transfer(refund)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Fixed/4-3-3a_Fixed.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: auctionFixed
- Function name: `withdrawRefund()`
- PC address: 299
- Estimated Gas Usage: 6944 - 61605

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Fixed/4-3-3a_Fixed.sol:18

#### Code

```
msg.sender.transfer(refund)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: withdrawRefund(), txdata: 0x110f8874, value: 0x0


