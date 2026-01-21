**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [controlled-delegatecall](#controlled-delegatecall) (1 results) (High)
 - [unchecked-lowlevel](#unchecked-lowlevel) (2 results) (Medium)
 - [missing-zero-check](#missing-zero-check) (1 results) (Low)
 - [solc-version](#solc-version) (1 results) (Informational)
 - [low-level-calls](#low-level-calls) (2 results) (Informational)
 - [immutable-states](#immutable-states) (3 results) (Optimization)
## controlled-delegatecall
Impact: High
Confidence: Medium
 - [ ] ID-0
[HackMe.fallback()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L15-L16) uses delegatecall to a input-controlled function id
	- [address(lib).delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L15-L16


## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[HackMe.fallback()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L15-L16) ignores return value by [address(lib).delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L15-L16


 - [ ] ID-2
[Attack.attack()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L24-L25) ignores return value by [hackMe.call(abi.encodeWithSignature(pwn()))](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L25)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L24-L25


## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-3
[Attack.constructor(address)._hackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L21) lacks a zero-check on :
		- [hackMe = _hackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L22)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L21


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-4
Version constraint 0.8.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- FullInlinerNonExpressionSplitArgumentEvaluationOrder
	- MissingSideEffectsOnSelectorAccess
	- AbiReencodingHeadOverflowWithStaticArrayCleanup
	- DirtyBytesArrayToStorage
	- DataLocationChangeInInternalOverride
	- NestedCalldataArrayAbiReencodingSizeValidation
	- SignedImmutables
	- ABIDecodeTwoDimensionalArrayMemory
	- KeccakCaching.
It is used by:
	- [0.8.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-5
Low level call in [HackMe.fallback()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L15-L16):
	- [address(lib).delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L15-L16


 - [ ] ID-6
Low level call in [Attack.attack()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L24-L25):
	- [hackMe.call(abi.encodeWithSignature(pwn()))](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L25)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L24-L25


## immutable-states
Impact: Optimization
Confidence: High
 - [ ] ID-7
[HackMe.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L9) should be immutable 

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L9


 - [ ] ID-8
[Attack.hackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L20) should be immutable 

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L20


 - [ ] ID-9
[HackMe.lib](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L10) should be immutable 

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Bug/1-6a_Bug.sol#L10


