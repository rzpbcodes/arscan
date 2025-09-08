**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [unchecked-lowlevel](#unchecked-lowlevel) (1 results) (Medium)
 - [missing-zero-check](#missing-zero-check) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[ReturnValue.callnotchecked(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L5-L7) ignores return value by [callee.call()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L6)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L5-L7


## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-1
[ReturnValue.callnotchecked(address).callee](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L5) lacks a zero-check on :
		- [callee.call()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L6)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L5


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
Version constraint 0.4.25 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- ABIEncoderV2PackedStorage_0.4.x.
It is used by:
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L1


 - [ ] ID-3
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-4
Low level call in [ReturnValue.callnotchecked(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L5-L7):
	- [callee.call()](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L6)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-3-3a_Bug/1-3-3a_Bug.sol#L5-L7


