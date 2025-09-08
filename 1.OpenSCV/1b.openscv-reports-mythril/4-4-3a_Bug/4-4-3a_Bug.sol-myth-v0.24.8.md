## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-3a_Bug/4-4-3a_Bug.sol
### Strict Ether balance check
- SWC ID: 132 in Contract `GuessTheNumber`
- Function name: `guess(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-3a_Bug/4-4-3a_Bug.sol:33
```
n == _secretNumber
```
### Strict Ether balance check
- SWC ID: 132 in Contract `GuessTheNumber`
- Function name: `getValue()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-3a_Bug/4-4-3a_Bug.sol:33
```
n == _secretNumber
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-3a_Bug/4-4-3a_Bug.sol

## Strict Ether balance check
- SWC ID: 132
- Severity: Low
- Contract: GuessTheNumber
- Function name: `guess(uint256)`
- PC address: 458

#### Description

Use of strict ether balance checking
Ether can be forcefully sent to this contract, This may make the contract unusable.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-3a_Bug/4-4-3a_Bug.sol:33

#### Code

```
n == _secretNumber
```

#### Initial State:

Account: [CREATOR], balance: 0x35000000000000000, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [CREATOR], function: guess(uint256), txdata: 0x9189fec10808080808080808080808080808080808080808080808080808080808080808, decoded_data: (3632692995680508091719874039488248089514352460098527499277100674758058969096,), value: 0xde0b6b3a7640000
Caller: [SOMEGUY], function: guess(uint256), txdata: 0x9189fec10808080808080808080808080808080808080808080808080808080808080808, decoded_data: (3632692995680508091719874039488248089514352460098527499277100674758058969096,), value: 0xde0b6b3a7640000


## Strict Ether balance check
- SWC ID: 132
- Severity: Low
- Contract: GuessTheNumber
- Function name: `getValue()`
- PC address: 458

#### Description

Use of strict ether balance checking
Ether can be forcefully sent to this contract, This may make the contract unusable.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-3a_Bug/4-4-3a_Bug.sol:33

#### Code

```
n == _secretNumber
```

#### Initial State:

Account: [CREATOR], balance: 0x803, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: guess(uint256), txdata: 0x9189fec10000000000000000000000000000000000000000000000000000000000000000, decoded_data: (0,), value: 0xde0b6b3a7640000
Caller: [ATTACKER], function: getValue(), txdata: 0x20965255, value: 0x0


