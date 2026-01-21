**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (5 results) (Informational)
 - [external-function](#external-function) (1 results) (Optimization)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L1


 - [ ] ID-1
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-2
Parameter [Game.Try(string)._response](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L8) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L8


 - [ ] ID-3
Function [Game.StartGame(string,string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15-L22) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15-L22


 - [ ] ID-4
Function [Game.Try(string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L8-L13) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L8-L13


 - [ ] ID-5
Parameter [Game.StartGame(string,string)._question](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15


 - [ ] ID-6
Parameter [Game.StartGame(string,string)._response](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15


## external-function
Impact: Optimization
Confidence: High
 - [ ] ID-7
StartGame(string,string) should be declared external:
	- [Game.StartGame(string,string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15-L22)

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-2a_Bug/7-2-2a_Bug.sol#L15-L22


