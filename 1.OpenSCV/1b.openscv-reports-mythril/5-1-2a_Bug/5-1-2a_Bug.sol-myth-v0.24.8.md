## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-2a_Bug/5-1-2a_Bug.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `EthTxOrderDependenceMinimal`
- Function name: `claimReward(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-2a_Bug/5-1-2a_Bug.sol:25
```
msg.sender.transfer(reward)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `EthTxOrderDependenceMinimal`
- Function name: `claimReward(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-2a_Bug/5-1-2a_Bug.sol:25
```
msg.sender.transfer(reward)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-2a_Bug/5-1-2a_Bug.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: EthTxOrderDependenceMinimal
- Function name: `claimReward(uint256)`
- PC address: 730
- Estimated Gas Usage: 8647 - 63588

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-2a_Bug/5-1-2a_Bug.sol:25

#### Code

```
msg.sender.transfer(reward)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: claimReward(uint256), txdata: 0xae169a500000000000000000000000000000000000000000000000000000000000000000, decoded_data: (0,), value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: EthTxOrderDependenceMinimal
- Function name: `claimReward(uint256)`
- PC address: 730
- Estimated Gas Usage: 8647 - 63588

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-2a_Bug/5-1-2a_Bug.sol:25

#### Code

```
msg.sender.transfer(reward)
```

#### Initial State:

Account: [CREATOR], balance: 0x20001000000000000, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x4008000407ffffff, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: setReward(), txdata: 0x3eb6a67e, value: 0x1
Caller: [ATTACKER], function: claimReward(uint256), txdata: 0xae169a500000000000000000000000000000000000000000000000000000000000000002, decoded_data: (2,), value: 0x0


