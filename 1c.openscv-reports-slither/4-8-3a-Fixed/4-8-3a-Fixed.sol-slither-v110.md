**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [suicidal](#suicidal) (1 results) (High)
 - [unchecked-lowlevel](#unchecked-lowlevel) (1 results) (Medium)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
## suicidal
Impact: High
Confidence: High
 - [ ] ID-0
[DeprecatedSimpleFixed.useDeprecatedFixed()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L5-L23) allows anyone to destruct the contract

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L5-L23


## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[DeprecatedSimpleFixed.useDeprecatedFixed()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L5-L23) ignores return value by [address(this).delegatecall()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L5-L23


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
Version constraint ^0.4.24 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- DirtyBytesArrayToStorage
	- ABIDecodeTwoDimensionalArrayMemory
	- KeccakCaching
	- EmptyByteArrayCopy
	- DynamicArrayCleanup
	- ImplicitConstructorCallvalueCheck
	- TupleAssignmentMultiStackSlotComponents
	- MemoryArrayCreationOverflow
	- privateCanBeOverridden
	- SignedArrayStorageCopy
	- ABIEncoderV2StorageArrayWithMultiSlotElement
	- DynamicConstructorArgumentsClippedABIV2
	- UninitializedFunctionPointerInConstructor_0.4.x
	- IncorrectEventSignatureInLibraries_0.4.x
	- ABIEncoderV2PackedStorage_0.4.x
	- ExpExponentCleanup
	- EventStructWrongData.
It is used by:
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L1


 - [ ] ID-3
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-4
Low level call in [DeprecatedSimpleFixed.useDeprecatedFixed()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L5-L23):
	- [address(this).delegatecall()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Fixed/4-8-3a-Fixed.sol#L5-L23


