## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-8-3a-Fixed/4-8-3a-Fixed.sol
### Unprotected Selfdestruct
- SWC ID: 106 in Contract `DeprecatedSimpleFixed`
- Function name: `useDeprecatedFixed()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-8-3a-Fixed/4-8-3a-Fixed.sol:22
```
selfdestruct(address(0))
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-8-3a-Fixed/4-8-3a-Fixed.sol

## Unprotected Selfdestruct
- SWC ID: 106
- Severity: High
- Contract: DeprecatedSimpleFixed
- Function name: `useDeprecatedFixed()`
- PC address: 347
- Estimated Gas Usage: 1368 - 39273

#### Description

Any sender can cause the contract to self-destruct.
Any sender can trigger execution of the SELFDESTRUCT instruction to destroy this contract account. Review the transaction trace generated for this issue and make sure that appropriate security controls are in place to prevent unrestricted access.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-8-3a-Fixed/4-8-3a-Fixed.sol:22

#### Code

```
selfdestruct(address(0))
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: useDeprecatedFixed(), txdata: 0x46d3bdee, value: 0x0


