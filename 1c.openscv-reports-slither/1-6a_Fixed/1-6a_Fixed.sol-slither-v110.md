**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [controlled-delegatecall](#controlled-delegatecall) (1 results) (High)
 - [unchecked-lowlevel](#unchecked-lowlevel) (2 results) (Medium)
 - [missing-zero-check](#missing-zero-check) (1 results) (Low)
 - [solc-version](#solc-version) (1 results) (Informational)
 - [low-level-calls](#low-level-calls) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
 - [immutable-states](#immutable-states) (3 results) (Optimization)
## controlled-delegatecall
Impact: High
Confidence: Medium
 - [ ] ID-0
[HackMe.fallback()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L14-L15) uses delegatecall to a input-controlled function id
	- [address(lib).delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L15)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L14-L15


## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[HackMe.fallback()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L14-L15) ignores return value by [address(lib).delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L15)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L14-L15


 - [ ] ID-2
[Attack.attack()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L23-L24) ignores return value by [hackMe.call(abi.encodeWithSignature(pwn()))](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L24)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L23-L24


## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-3
[Attack.constructor(address)._hackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L20) lacks a zero-check on :
		- [hackMe = _hackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L21)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L20


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
	- [0.8.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-5
Low level call in [HackMe.fallback()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L14-L15):
	- [address(lib).delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L15)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L14-L15


 - [ ] ID-6
Low level call in [Attack.attack()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L23-L24):
	- [hackMe.call(abi.encodeWithSignature(pwn()))](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L24)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L23-L24


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-7
Variable [HackMe.owner_HackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L9) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L9


## immutable-states
Impact: Optimization
Confidence: High
 - [ ] ID-8
[Attack.hackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L19) should be immutable 

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L19


 - [ ] ID-9
[HackMe.lib](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L10) should be immutable 

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L10


 - [ ] ID-10
[HackMe.owner_HackMe](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L9) should be immutable 

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-6a_Fixed/1-6a_Fixed.sol#L9


