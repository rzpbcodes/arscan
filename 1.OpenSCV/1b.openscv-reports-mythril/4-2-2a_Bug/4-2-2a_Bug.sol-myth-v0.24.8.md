## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-2a_Bug/4-2-2a_Bug.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `Missing`
- Function name: `withdraw()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-2a_Bug/4-2-2a_Bug.sol:23
```
owner.transfer(this.balance)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `Missing`
- Function name: `withdraw()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-2a_Bug/4-2-2a_Bug.sol:23
```
owner.transfer(this.balance)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-2a_Bug/4-2-2a_Bug.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: Missing
- Function name: `withdraw()`
- PC address: 319
- Estimated Gas Usage: 3357 - 38298

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-2a_Bug/4-2-2a_Bug.sol:23

#### Code

```
owner.transfer(this.balance)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: Constructor(), txdata: 0x8a3c44a5, value: 0x0
Caller: [ATTACKER], function: withdraw(), txdata: 0x3ccfd60b, value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: Missing
- Function name: `withdraw()`
- PC address: 319
- Estimated Gas Usage: 3357 - 38298

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-2-2a_Bug/4-2-2a_Bug.sol:23

#### Code

```
owner.transfer(this.balance)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: Constructor(), txdata: 0x8a3c44a5, value: 0x0
Caller: [ATTACKER], function: withdraw(), txdata: 0x3ccfd60b, value: 0x0


