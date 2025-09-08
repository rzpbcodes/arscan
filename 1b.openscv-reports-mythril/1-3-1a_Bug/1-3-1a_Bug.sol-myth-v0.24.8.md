## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-1a_Bug/1-3-1a_Bug.sol
### External Call To User-Supplied Address
- SWC ID: 107 in Contract `ContractERP`
- Function name: `newPurchaseOrder(address)`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-1a_Bug/1-3-1a_Bug.sol:16
```
product.addProduct()
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-1a_Bug/1-3-1a_Bug.sol

## External Call To User-Supplied Address
- SWC ID: 107
- Severity: Low
- Contract: ContractERP
- Function name: `newPurchaseOrder(address)`
- PC address: 151
- Estimated Gas Usage: 2315 - 36972

#### Description

A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed. Note that the callee account might contain arbitrary code and could re-enter any function within this contract. Reentering the contract in an intermediate state may lead to unexpected behaviour. Make sure that no state modifications are executed after this call and/or reentrancy guards are in place.
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/1-3-1a_Bug/1-3-1a_Bug.sol:16

#### Code

```
product.addProduct()
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [ATTACKER], function: newPurchaseOrder(address), txdata: 0xa2e75a5a000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef, decoded_data: ('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',), value: 0x0


