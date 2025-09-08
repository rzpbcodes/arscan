**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (1 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
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
	- [0.8.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-2a_Fixed/4-8-2a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-2a_Fixed/4-8-2a_Fixed.sol#L1


