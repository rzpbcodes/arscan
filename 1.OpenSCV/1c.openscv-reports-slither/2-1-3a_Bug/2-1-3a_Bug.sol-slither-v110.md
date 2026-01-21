**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [uninitialized-state](#uninitialized-state) (1 results) (High)
 - [calls-loop](#calls-loop) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [cache-array-length](#cache-array-length) (1 results) (Optimization)
## uninitialized-state
Impact: High
Confidence: High
 - [ ] ID-0
[Refunder.refunds](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L6) is never initialized. It is used in:
	- [Refunder.refundAll()](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L14-L18)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L6


## calls-loop
Impact: Low
Confidence: Medium
 - [ ] ID-1
[Refunder.refundAll()](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L14-L18) has external calls inside a loop: [require(bool)(refundAddresses[x].send(refunds[refundAddresses[x]]))](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L14-L18


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
Version constraint 0.4.24 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L1


## cache-array-length
Impact: Optimization
Confidence: High
 - [ ] ID-4
Loop condition [x < refundAddresses.length](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L15) should use cached array length instead of referencing `length` member of the storage array.
 
../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-3a_Bug/2-1-3a_Bug.sol#L15


