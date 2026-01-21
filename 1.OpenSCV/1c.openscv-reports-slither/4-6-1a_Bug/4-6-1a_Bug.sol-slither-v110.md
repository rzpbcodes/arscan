**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [erc20-interface](#erc20-interface) (1 results) (Medium)
 - [shadowing-local](#shadowing-local) (3 results) (Low)
 - [dead-code](#dead-code) (2 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [too-many-digits](#too-many-digits) (1 results) (Informational)
## erc20-interface
Impact: Medium
Confidence: High
 - [ ] ID-0
[MyERC20](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L142-L393) has incorrect ERC20 function interface:[MyERC20.transfer(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L218-L221)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L142-L393


## shadowing-local
Impact: Low
Confidence: High
 - [ ] ID-1
[MyERC20.constructor(string,string,uint8).name](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154) shadows:
	- [MyERC20.name()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L165-L167) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154


 - [ ] ID-2
[MyERC20.constructor(string,string,uint8).symbol](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154) shadows:
	- [MyERC20.symbol()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L173-L175) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154


 - [ ] ID-3
[MyERC20.constructor(string,string,uint8).decimals](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154) shadows:
	- [MyERC20.decimals()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L189-L191) (function)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154


## dead-code
Impact: Informational
Confidence: Medium
 - [ ] ID-4
[MyERC20._burn(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L347-L353) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L347-L353


 - [ ] ID-5
[MyERC20._burnFrom(address,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L382-L385) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L382-L385


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
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L1


## too-many-digits
Impact: Informational
Confidence: Medium
 - [ ] ID-8
[MyERC20.constructor(string,string,uint8)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154-L160) uses literals with too many digits:
	- [_mint(msg.sender,100000 * 10 ** uint256(decimals))](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L159)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-1a_Bug/4-6-1a_Bug.sol#L154-L160


