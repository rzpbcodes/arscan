## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Bug/5-1-6a_Bug.sol
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `OwnableWallet`
- Function name: `withdraw(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Bug/5-1-6a_Bug.sol:13
```
owner.transfer(_amount)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Bug/5-1-6a_Bug.sol

## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: OwnableWallet
- Function name: `withdraw(uint256)`
- PC address: 387
- Estimated Gas Usage: 2733 - 37674

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Bug/5-1-6a_Bug.sol:13

#### Code

```
owner.transfer(_amount)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: initWallet(address), txdata: 0x9da8be21bebebebebebebebebebebebedeadbeefdeadbeefdeadbeefdeadbeefdeadbeef, value: 0x0
Caller: [ATTACKER], function: withdraw(uint256), txdata: 0x2e1a7d4d0000000000000000000000000000000000000000000000020000808002200004, decoded_data: (36893629434698924036,), value: 0x0


