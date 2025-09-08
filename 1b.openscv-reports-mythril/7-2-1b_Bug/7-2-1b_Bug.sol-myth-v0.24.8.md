## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-1b_Bug/7-2-1b_Bug.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `Vault`
- Function name: `unlock(address,bytes32)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-1b_Bug/7-2-1b_Bug.sol:13
```
_owner.transfer (this.balance)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `Vault`
- Function name: `unlock(address,bytes32)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-1b_Bug/7-2-1b_Bug.sol:13
```
_owner.transfer (this.balance)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-1b_Bug/7-2-1b_Bug.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: Vault
- Function name: `unlock(address,bytes32)`
- PC address: 223
- Estimated Gas Usage: 2553 - 36834

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-1b_Bug/7-2-1b_Bug.sol:13

#### Code

```
_owner.transfer (this.balance)
```

#### Initial State:

Account: [CREATOR], balance: 0x4, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: unlock(address,bytes32), txdata: 0x785fd544, value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: Vault
- Function name: `unlock(address,bytes32)`
- PC address: 223
- Estimated Gas Usage: 2553 - 36834

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/7-2-1b_Bug/7-2-1b_Bug.sol:13

#### Code

```
_owner.transfer (this.balance)
```

#### Initial State:

Account: [CREATOR], balance: 0x56800000010000000, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x4067071901c601000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: unlock(address,bytes32), txdata: 0x785fd544000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef, value: 0x0
Caller: [ATTACKER], function: unlock(address,bytes32), txdata: 0x785fd544, value: 0x0


