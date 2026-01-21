**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [boolean-equal](#boolean-equal) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
 - [external-function](#external-function) (2 results) (Optimization)
## boolean-equal
Impact: Informational
Confidence: High
 - [ ] ID-0
[Relayer.relay(Target,bytes)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13-L22) compares to a boolean constant:
	-[require(bool,string)(transactions[transactionId].executed == false,same transaction twice)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L15)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13-L22


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
Version constraint ^0.5.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- UninitializedFunctionPointerInConstructor
	- IncorrectEventSignatureInLibraries
	- ABIEncoderV2PackedStorage.
It is used by:
	- [^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-3
Low level call in [Relayer.relay(Target,bytes)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13-L22):
	- [(success,None) = address(target).call(abi.encodeWithSignature(execute(bytes),_data))](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L20)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13-L22


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-4
Parameter [Relayer.relay(Target,bytes)._data](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13


## external-function
Impact: Optimization
Confidence: High
 - [ ] ID-5
relay(Target,bytes) should be declared external:
	- [Relayer.relay(Target,bytes)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13-L22)
Moreover, the following function parameters should change its data location:
_data location should be calldata

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L13-L22


 - [ ] ID-6
execute(bytes) should be declared external:
	- [Target.execute(bytes)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L27-L29)
Moreover, the following function parameters should change its data location:
_data location should be calldata

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Bug/3-1a_Bug.sol#L27-L29


