## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Bug/4-3-3a_Bug.sol
### Transaction Order Dependence
- SWC ID: 114 in Contract `auction`
- Function name: `bid()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Bug/4-3-3a_Bug.sol:10
```
highestBidder.transfer(highestBid)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Bug/4-3-3a_Bug.sol

## Transaction Order Dependence
- SWC ID: 114
- Severity: Medium
- Contract: auction
- Function name: `bid()`
- PC address: 245
- Estimated Gas Usage: 15133 - 90404

#### Description

The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-3-3a_Bug/4-3-3a_Bug.sol:10

#### Code

```
highestBidder.transfer(highestBid)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x3, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0
Caller: [ATTACKER], function: bid(), txdata: 0x1998aeef, value: 0x0


