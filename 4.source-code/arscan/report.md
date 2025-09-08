**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [signedness](#signedness) (1 results) (Medium)
## signedness
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[Test.withdrawOnce(int256)](../../contracts/test-slither/test.sol#L9-L15) possible signedness bug in type conversion:- 
	- [msg.sender.transfer(uint256(amount))](../../contracts/test-slither/test.sol#L13)

../../contracts/test-slither/test.sol#L9-L15


