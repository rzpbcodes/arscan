**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [unused-return](#unused-return) (1 results) (Medium)
 - [solc-version](#solc-version) (1 results) (Informational)
## unused-return
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[ContractERP.newPurchaseOrder(Item)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Bug/1-3-1a_Bug.sol#L15-L18) ignores return value by [product.addProduct()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Bug/1-3-1a_Bug.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Bug/1-3-1a_Bug.sol#L15-L18


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
	- [0.8.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Bug/1-3-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-1a_Bug/1-3-1a_Bug.sol#L1


