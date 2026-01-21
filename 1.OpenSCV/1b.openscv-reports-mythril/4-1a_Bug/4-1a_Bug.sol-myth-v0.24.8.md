## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Bug/4-1a_Bug.sol
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `GuessTheRandomNumberChallenge`
- Function name: `guess(uint8)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Bug/4-1a_Bug.sol:19
```
msg.sender.transfer(2 ether)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Bug/4-1a_Bug.sol

## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: GuessTheRandomNumberChallenge
- Function name: `guess(uint8)`
- PC address: 259
- Estimated Gas Usage: 1851 - 36462

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-1a_Bug/4-1a_Bug.sol:19

#### Code

```
msg.sender.transfer(2 ether)
```

#### Initial State:

Account: [CREATOR], balance: 0xde0b74427880002, nonce:0, storage:{}
Account: [ATTACKER], balance: 0xde0b6b3a764064d, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0xde0b6b3a7640000
Caller: [SOMEGUY], function: guess(uint8), txdata: 0x4ba4c16b, value: 0xde0b6b3a7640000
Caller: [ATTACKER], function: guess(uint8), txdata: 0x4ba4c16b, value: 0xde0b6b3a7640000


