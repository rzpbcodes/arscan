**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [shadowing-local](#shadowing-local) (3 results) (Low)
 - [dead-code](#dead-code) (2 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [too-many-digits](#too-many-digits) (1 results) (Informational)
 - [unimplemented-functions](#unimplemented-functions) (1 results) (Informational)
 - [external-function](#external-function) (1 results) (Optimization)
## shadowing-local
Impact: Low
Confidence: High
 - [ ] ID-0
[MyERC20.constructor(string,string,uint8).name](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153) shadows:
	- [MyERC20.name()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L164-L166) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153


 - [ ] ID-1
[MyERC20.constructor(string,string,uint8).symbol](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153) shadows:
	- [MyERC20.symbol()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L172-L174) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153


 - [ ] ID-2
[MyERC20.constructor(string,string,uint8).decimals](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153) shadows:
	- [MyERC20.decimals()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L188-L190) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153


## dead-code
Impact: Informational
Confidence: Medium
 - [ ] ID-3
[MyERC20._burn(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L346-L352) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L346-L352


 - [ ] ID-4
[MyERC20._burnFrom(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L381-L384) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L381-L384


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-5
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-6
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
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L1


## too-many-digits
Impact: Informational
Confidence: Medium
 - [ ] ID-7
[MyERC20.constructor(string,string,uint8)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153-L159) uses literals with too many digits:
	- [_mint(msg.sender,100000 * 10 ** uint256(decimals))](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L158)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L153-L159


## unimplemented-functions
Impact: Informational
Confidence: High
 - [ ] ID-8
[MyERC20](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L141-L392) does not implement functions:
	- [IERC20.transfer(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L12)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L141-L392


## external-function
Impact: Optimization
Confidence: High
 - [ ] ID-9
transfer(address,string) should be declared external:
	- [MyERC20.transfer(address,string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L217-L220)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-3a_Bug/4-6-3a_Bug.sol#L217-L220


