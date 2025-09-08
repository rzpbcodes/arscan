**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [assembly](#assembly) (1 results) (Informational)
 - [boolean-equal](#boolean-equal) (1 results) (Informational)
 - [solc-version](#solc-version) (1 results) (Informational)
 - [var-read-using-this](#var-read-using-this) (1 results) (Optimization)
## assembly
Impact: Informational
Confidence: High
 - [ ] ID-0
[ProviderExample.contractExists(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L21-L27) uses assembly
	- [INLINE ASM](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L23-L25)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L21-L27


## boolean-equal
Impact: Informational
Confidence: High
 - [ ] ID-1
[ProviderExample.getService(address,address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L9-L18) compares to a boolean constant:
	-[this.contractExists(provider) == false](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L10)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L9-L18


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
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
	- [0.8.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L1


## var-read-using-this
Impact: Optimization
Confidence: High
 - [ ] ID-3
The function [ProviderExample.getService(address,address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L9-L18) reads [this.contractExists(provider) == false](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L10) with `this` which adds an extra STATICCALL.

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-2a_Fixed/1-3-2a_Fixed.sol#L9-L18


