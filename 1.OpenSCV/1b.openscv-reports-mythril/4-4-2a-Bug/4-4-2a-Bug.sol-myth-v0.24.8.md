## Summary results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-2a-Bug/4-4-2a-Bug.sol
### Exception State
- SWC ID: 110 in Contract `AssertMultiTx2`
- Function name: `run()`
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-2a-Bug/4-4-2a-Bug.sol:10
```
function run() {
        assert(param > 0);
    }
```
# Analysis results for /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-2a-Bug/4-4-2a-Bug.sol

## Exception State
- SWC ID: 110
- Severity: Medium
- Contract: AssertMultiTx2
- Function name: `run()`
- PC address: 149
- Estimated Gas Usage: 969 - 1064

#### Description

An assertion violation was triggered.
It is possible to trigger an assertion violation. Note that Solidity assert() statements should only be used to check invariants. Review the transaction trace generated for this issue and either make sure your program logic is correct, or use require() instead of assert() if your goal is to constrain user inputs or enforce preconditions. Remember to validate inputs from both callers (for instance, via passed arguments) and callees (for instance, via return values).
In file: /home/visual/contracts/3.OpenSCV/openscv-subfolders-mythril/4-4-2a-Bug/4-4-2a-Bug.sol:10

#### Code

```
function run() {
        assert(param > 0);
    }
```

#### Initial State:

Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

#### Transaction Sequence

Caller: [CREATOR], calldata: , decoded_data: , value: 0x0
Caller: [SOMEGUY], function: run(), txdata: 0xc0406226, value: 0x0


