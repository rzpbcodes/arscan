## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Fixed/5-1-6a_Fixed.sol
### Unchecked return value from external call.
- SWC ID: 104 in Contract `Wallet`
- Function name: `withdraw()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Fixed/5-1-6a_Fixed.sol:13
```
walletLibrary.delegatecall(msg.data)
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Fixed/5-1-6a_Fixed.sol

## Unchecked return value from external call.
- SWC ID: 104
- Severity: Medium
- Contract: Wallet
- Function name: `withdraw()`
- PC address: 185
- Estimated Gas Usage: 1076 - 37944

#### Description

The return value of a message call is not checked.
External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller. The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/5-1-6a_Fixed/5-1-6a_Fixed.sol:13

#### Code

```
walletLibrary.delegatecall(msg.data)
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: deposit(), txdata: 0xd0e30db0, value: 0x0
Caller: [CREATOR], function: withdraw(), txdata: 0x3ccfd60b, value: 0x0


