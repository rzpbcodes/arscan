## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Bug/5-1-5a_Bug.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `AmountSender`
- Function name: `setTransferAmount(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Bug/5-1-5a_Bug.sol:34
```
msg.sender.transfer(amount)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `AmountSender`
- Function name: `setTransferAmount(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Bug/5-1-5a_Bug.sol:34
```
msg.sender.transfer(amount)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Bug/5-1-5a_Bug.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: AmountSender
- Function name: `setTransferAmount(uint256)`
- PC address: 543
- Estimated Gas Usage: 1828 - 36109

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Bug/5-1-5a_Bug.sol:34

#### Code

```
msg.sender.transfer(amount)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: setTransferAmount(uint256), txdata: 0x81c82233, value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: AmountSender
- Function name: `setTransferAmount(uint256)`
- PC address: 543
- Estimated Gas Usage: 1828 - 36109

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Bug/5-1-5a_Bug.sol:34

#### Code

```
msg.sender.transfer(amount)
```

#### Initial State:

Account: [CREATOR], balance: 0x56bc44c2c630fffff, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x522821000000, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: setTransferAmount(uint256), txdata: 0x81c82233, value: 0x0
Caller: [ATTACKER], function: setTransferAmount(uint256), txdata: 0x81c82233, value: 0x0


