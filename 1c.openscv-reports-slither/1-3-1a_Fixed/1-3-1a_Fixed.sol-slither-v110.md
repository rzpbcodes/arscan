**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [boolean-equal](#boolean-equal) (1 results) (Informational)
 - [solc-version](#solc-version) (1 results) (Informational)
## boolean-equal
Impact: Informational
Confidence: High
 - [ ] ID-0
[ContractERP.newPurchaseOrder(Item)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Fixed/1-3-1a_Fixed.sol#L11-L16) compares to a boolean constant:
	-[result == true](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Fixed/1-3-1a_Fixed.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Fixed/1-3-1a_Fixed.sol#L11-L16


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
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
	- [0.8.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Fixed/1-3-1a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Fixed/1-3-1a_Fixed.sol#L1


