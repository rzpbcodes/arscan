**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [unchecked-lowlevel](#unchecked-lowlevel) (1 results) (Medium)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[Wallet.withdraw()](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L12-L14) ignores return value by [walletLibrary.delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L12-L14


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
Version constraint 0.5.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-3
Low level call in [Wallet.withdraw()](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L12-L14):
	- [walletLibrary.delegatecall(msg.data)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L12-L14


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-4
Constant [Wallet.walletLibrary](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L5) is not in UPPER_CASE_WITH_UNDERSCORES

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Fixed/5-1-6a_Fixed.sol#L5


