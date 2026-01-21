**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [unchecked-lowlevel](#unchecked-lowlevel) (1 results) (Medium)
 - [missing-zero-check](#missing-zero-check) (1 results) (Low)
 - [pragma](#pragma) (1 results) (Informational)
 - [solc-version](#solc-version) (3 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[NewContract.doSomething(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15-L18) ignores return value by [_addr.call(abi.encodeWithSignature(myFunction()))](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15-L18


## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-1
[NewContract.doSomething(address)._addr](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15) lacks a zero-check on :
		- [_addr.call(abi.encodeWithSignature(myFunction()))](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15


## pragma
Impact: Informational
Confidence: High
 - [ ] ID-2
2 different versions of Solidity are used:
	- Version constraint ^0.5.0 is used by:
		-[^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L2)
	- Version constraint >=0.5.0<0.9.0 is used by:
		-[>=0.5.0<0.9.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L2


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-3
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-4
Version constraint >=0.5.0<0.9.0 is too complex.
It is used by:
	- [>=0.5.0<0.9.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L13


 - [ ] ID-5
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
	- [^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L2)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L2


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-6
Low level call in [NewContract.doSomething(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15-L18):
	- [_addr.call(abi.encodeWithSignature(myFunction()))](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15-L18


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-7
Parameter [NewContract.doSomething(address)._addr](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-5a_Fixed/1-5a_Fixed.sol#L15


