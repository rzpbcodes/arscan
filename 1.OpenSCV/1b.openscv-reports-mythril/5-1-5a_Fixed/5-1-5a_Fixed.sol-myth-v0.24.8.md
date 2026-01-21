## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Fixed/5-1-5a_Fixed.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `AmountSender`
- Function name: `setTransferAmount(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Fixed/5-1-5a_Fixed.sol:37
```
msg.sender.transfer(amount)
```
### Unprotected Ether Withdrawal
- SWC ID: 105 in Contract `AmountSender`
- Function name: `setTransferAmount(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Fixed/5-1-5a_Fixed.sol:37
```
msg.sender.transfer(amount)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Fixed/5-1-5a_Fixed.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: AmountSender
- Function name: `setTransferAmount(uint256)`
- PC address: 586
- Estimated Gas Usage: 2721 - 37002

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Fixed/5-1-5a_Fixed.sol:37

#### Code

```
msg.sender.transfer(amount)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: setAmountOp1(uint256), txdata: 0x00c847ca, value: 0x0
Caller: [ATTACKER], function: setTransferAmount(uint256), txdata: 0x81c82233, value: 0x0


## Unprotected Ether Withdrawal
- SWC ID: 105
- Severity: High
- Contract: AmountSender
- Function name: `setTransferAmount(uint256)`
- PC address: 586
- Estimated Gas Usage: 2721 - 37002

#### Description

Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-5a_Fixed/5-1-5a_Fixed.sol:37

#### Code

```
msg.sender.transfer(amount)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0xdebf6ff9ffe74734, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: setAmountOp1(uint256), txdata: 0x00c847ca000000000000000000000000000000000000000000000003, decoded_data: (55340232221128654848,), value: 0x0
Caller: [ATTACKER], function: setTransferAmount(uint256), txdata: 0x81c82233, value: 0x0


