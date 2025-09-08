## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-1a_Bug/5-1-1a_Bug.sol
### Unchecked return value from external call.
- SWC ID: 104 in Contract `Test`
- Function name: `pay()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-1a_Bug/5-1-1a_Bug.sol:8
```
msg.sender.send(100)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `Test`
- Function name: `pay()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-1a_Bug/5-1-1a_Bug.sol:8
```
msg.sender.send(100)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-1a_Bug/5-1-1a_Bug.sol

## Unchecked return value from external call.
- SWC ID: 104
- Severity: Medium
- Contract: Test
- Function name: `pay()`
- PC address: 158
- Estimated Gas Usage: 1773 - 36054

#### Description

The return value of a message call is not checked.
External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller. The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-1a_Bug/5-1-1a_Bug.sol:8

#### Code

```
msg.sender.send(100)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: pay(), txdata: 0x1b9265b8, value: 0x0
Caller: [CREATOR], function: pay(), txdata: 0x1b9265b8, value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: Test
- Function name: `pay()`
- PC address: 158
- Estimated Gas Usage: 1773 - 36054

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-1a_Bug/5-1-1a_Bug.sol:8

#### Code

```
msg.sender.send(100)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x400000800, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: pay(), txdata: 0x1b9265b8, value: 0x0
Caller: [ATTACKER], function: pay(), txdata: 0x1b9265b8, value: 0x0


