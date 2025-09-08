**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [unchecked-lowlevel](#unchecked-lowlevel) (1 results) (Medium)
 - [boolean-equal](#boolean-equal) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
 - [naming-convention](#naming-convention) (3 results) (Informational)
 - [external-function](#external-function) (2 results) (Optimization)
## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[Relayer.relay(Target,bytes,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21) ignores return value by [address(target).call(abi.encodeWithSignature(execute(bytes),_data,_gasLimit))](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L20)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21


## boolean-equal
Impact: Informational
Confidence: High
 - [ ] ID-1
[Relayer.relay(Target,bytes,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21) compares to a boolean constant:
	-[require(bool,string)(transactions[transactionId].executed == false,same transaction twice)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L15)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
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
	- [^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-4
Low level call in [Relayer.relay(Target,bytes,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21):
	- [address(target).call(abi.encodeWithSignature(execute(bytes),_data,_gasLimit))](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L20)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-5
Parameter [Relayer.relay(Target,bytes,uint256)._gasLimit](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13


 - [ ] ID-6
Parameter [Relayer.relay(Target,bytes,uint256)._data](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13


 - [ ] ID-7
Parameter [Target.execute(bytes,uint256)._gasLimit](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L26) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L26


## external-function
Impact: Optimization
Confidence: High
 - [ ] ID-8
execute(bytes,uint256) should be declared external:
	- [Target.execute(bytes,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L26-L29)
Moreover, the following function parameters should change its data location:
_data location should be calldata

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L26-L29


 - [ ] ID-9
relay(Target,bytes,uint256) should be declared external:
	- [Relayer.relay(Target,bytes,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21)
Moreover, the following function parameters should change its data location:
_data location should be calldata

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-1a_Fixed/3-1a_Fixed.sol#L13-L21


