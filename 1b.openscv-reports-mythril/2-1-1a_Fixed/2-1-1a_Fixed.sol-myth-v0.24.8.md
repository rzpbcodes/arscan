## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Fixed/2-1-1a_Fixed.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `Fixed`
- Function name: `withdraw(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Fixed/2-1-1a_Fixed.sol:7
```
msg.sender.call.value(amount)('100')
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `Fixed`
- Function name: `withdraw(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Fixed/2-1-1a_Fixed.sol:7
```
msg.sender.call.value(amount)('100')
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Fixed/2-1-1a_Fixed.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: Fixed
- Function name: `withdraw(uint256)`
- PC address: 200
- Estimated Gas Usage: 1013 - 35389

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Fixed/2-1-1a_Fixed.sol:7

#### Code

```
msg.sender.call.value(amount)('100')
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: withdraw(uint256), txdata: 0x2e1a7d4d, value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: Fixed
- Function name: `withdraw(uint256)`
- PC address: 200
- Estimated Gas Usage: 1013 - 35389

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/2-1-1a_Fixed/2-1-1a_Fixed.sol:7

#### Code

```
msg.sender.call.value(amount)('100')
```

#### Initial State:

Account: [CREATOR], balance: 0x2e1b6680000000000, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x51e4996ffffcfffff, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: withdraw(uint256), txdata: 0x2e1a7d4d, value: 0x0
Caller: [ATTACKER], function: withdraw(uint256), txdata: 0x2e1a7d4d000000000000000000000000000000000000000000000002, decoded_data: (36893488147419103232,), value: 0x0


