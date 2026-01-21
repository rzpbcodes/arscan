## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Bug/2-1-1a_Bug.sol
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `Vulnerable`
- Function name: `withdraw(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Bug/2-1-1a_Bug.sol:7
```
msg.sender.transfer(amount)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Bug/2-1-1a_Bug.sol

## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: Vulnerable
- Function name: `withdraw(uint256)`
- PC address: 158
- Estimated Gas Usage: 997 - 35278

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Bug/2-1-1a_Bug.sol:7

#### Code

```
msg.sender.transfer(amount)
```

#### Initial State:

Account: [CREATOR], balance: 0x400a010020000000, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x20000000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: withdraw(uint256), txdata: 0x2e1a7d4d, value: 0x0
Caller: [ATTACKER], function: withdraw(uint256), txdata: 0x2e1a7d4d000000000000000000000000000000000000000000000004, decoded_data: (73786976294838206464,), value: 0x0


