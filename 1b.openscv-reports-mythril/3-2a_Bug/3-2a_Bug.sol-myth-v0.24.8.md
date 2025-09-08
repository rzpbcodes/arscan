## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/3-2a_Bug/3-2a_Bug.sol
### Unchecked return value from external call.
- SWC ID: 104 in Contract `HardcodedNotGood`
- Function name: `doSend(uint256)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/3-2a_Bug/3-2a_Bug.sol:20
```
_callable.send(amount)
```
### Unchecked return value from external call.
- SWC ID: 104 in Contract `HardcodedNotGood`
- Function name: `callLowLevel()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/3-2a_Bug/3-2a_Bug.sol:24
```
_callable.call.value(0).gas(10000)("")
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/3-2a_Bug/3-2a_Bug.sol

## Unchecked return value from external call.
- SWC ID: 104
- Severity: Medium
- Contract: HardcodedNotGood
- Function name: `doSend(uint256)`
- PC address: 274
- Estimated Gas Usage: 1826 - 36437

#### Description

The return value of a message call is not checked.
External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller. The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/3-2a_Bug/3-2a_Bug.sol:20

#### Code

```
_callable.send(amount)
```

#### Initial State:

Account: [CREATOR], balance: 0x2, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: callLowLevel(), txdata: 0xf7cfff49, value: 0x0
Caller: [SOMEGUY], function: doSend(uint256), txdata: 0x2ff9a6960000000000000000000000000000000000000000000000000040000000002010, decoded_data: (18014398509490192,), value: 0x0


## Unchecked return value from external call.
- SWC ID: 104
- Severity: Medium
- Contract: HardcodedNotGood
- Function name: `callLowLevel()`
- PC address: 610
- Estimated Gas Usage: 1919 - 36813

#### Description

The return value of a message call is not checked.
External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller. The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/3-2a_Bug/3-2a_Bug.sol:24

#### Code

```
_callable.call.value(0).gas(10000)("")
```

#### Initial State:

Account: [CREATOR], balance: 0x40000000001, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: callLowLevel(), txdata: 0xf7cfff49, value: 0x0
Caller: [SOMEGUY], function: callLowLevel(), txdata: 0xf7cfff49, value: 0x0


