## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-2a_Fixed/4-3-2a_Fixed.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `TestContract`
- Function name: `withdrawAll()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-2a_Fixed/4-3-2a_Fixed.sol:50
```
msg.sender.transfer(this.balance)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `TestContract`
- Function name: `withdrawAll()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-2a_Fixed/4-3-2a_Fixed.sol:50
```
msg.sender.transfer(this.balance)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-2a_Fixed/4-3-2a_Fixed.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: TestContract
- Function name: `withdrawAll()`
- PC address: 789
- Estimated Gas Usage: 2629 - 37430

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-2a_Fixed/4-3-2a_Fixed.sol:50

#### Code

```
msg.sender.transfer(this.balance)
```

#### Initial State:

Account: [CREATOR], balance: 0x1, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: newOwner(address), txdata: 0x85952454000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef, decoded_data: ('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',), value: 0x0
Caller: [ATTACKER], function: withdrawAll(), txdata: 0x853828b6, value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: TestContract
- Function name: `withdrawAll()`
- PC address: 789
- Estimated Gas Usage: 2629 - 37430

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-2a_Fixed/4-3-2a_Fixed.sol:50

#### Code

```
msg.sender.transfer(this.balance)
```

#### Initial State:

Account: [CREATOR], balance: 0x40000000000000001, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x10800000000000000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: newOwner(address), txdata: 0x85952454000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef, decoded_data: ('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',), value: 0x0
Caller: [ATTACKER], function: withdrawAll(), txdata: 0x853828b6, value: 0x0


