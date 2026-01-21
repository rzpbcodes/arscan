**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [controlled-array-length](#controlled-array-length) (1 results) (High)
 - [solc-version](#solc-version) (2 results) (Informational)
## controlled-array-length
Impact: High
Confidence: Medium
 - [ ] ID-0
[Oracle](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-10-1a_Fixed/4-10-1a_Fixed.sol#L3-L22) contract sets array length with a user-controlled value:
	- [requests.push(Request(data,callback))](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-10-1a_Fixed/4-10-1a_Fixed.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-10-1a_Fixed/4-10-1a_Fixed.sol#L3-L22


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.4.22 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
Version constraint >=0.4.22<0.9.0 is too complex.
It is used by:
	- [>=0.4.22<0.9.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-10-1a_Fixed/4-10-1a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-10-1a_Fixed/4-10-1a_Fixed.sol#L1


