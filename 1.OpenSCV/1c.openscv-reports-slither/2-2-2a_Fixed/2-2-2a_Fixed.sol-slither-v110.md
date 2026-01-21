**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [shadowing-local](#shadowing-local) (3 results) (Low)
 - [dead-code](#dead-code) (2 results) (Informational)
 - [deprecated-standards](#deprecated-standards) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [too-many-digits](#too-many-digits) (1 results) (Informational)
## shadowing-local
Impact: Low
Confidence: High
 - [ ] ID-0
[MyERC20.constructor(string,string,uint8).name](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153) shadows:
	- [MyERC20.name()](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L164-L166) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153


 - [ ] ID-1
[MyERC20.constructor(string,string,uint8).symbol](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153) shadows:
	- [MyERC20.symbol()](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L172-L174) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153


 - [ ] ID-2
[MyERC20.constructor(string,string,uint8).decimals](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153) shadows:
	- [MyERC20.decimals()](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L188-L190) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153


## dead-code
Impact: Informational
Confidence: Medium
 - [ ] ID-3
[MyERC20._burn(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L357-L363) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L357-L363


 - [ ] ID-4
[MyERC20._burnFrom(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L392-L395) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L392-L395


## deprecated-standards
Impact: Informational
Confidence: High
 - [ ] ID-5
Deprecated standard detected [THROW](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L226):
	- Usage of "throw" should be replaced with "revert()"

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L226


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-6
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-7
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
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L1


## too-many-digits
Impact: Informational
Confidence: Medium
 - [ ] ID-8
[MyERC20.constructor(string,string,uint8)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153-L159) uses literals with too many digits:
	- [_mint(msg.sender,100000 * 10 ** uint256(decimals))](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L158)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-2-2a_Fixed/2-2-2a_Fixed.sol#L153-L159


