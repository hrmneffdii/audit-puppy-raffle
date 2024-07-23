### [M-1] Looping through the players array to check for duplicate in `PuppleRuffle::enterRaffle` could potentially lead to Denial of Service (DoS) attack, increasing gas cost in the future

**Description :** The `PuppleRuffle::enterRaffle` function includes a duplicate checking mechanism that loops through the `players` array. As the array lengthens, the increasing number of iterations required for duplicate checks can result in higher gas costs. Consequently, `players` who enter earlier may incur lower gas costs compared to those who enter later

**Impact :** The impact is two-fold.
1. The gas cost for raffle entrants will greatly increase as more players enter the raffle
2. Front running opportunities are created for malicious user to increase gas cost of other user, so their transaction fails. 

**Proof of Concepts :** If we have 2 sets of scenario for entrance the ruffle, first set contain 100 player as well as second set. 
- First scenario : 6252041
- Second scenario : 18068131

This due to the for loop in the `PuppleRuffle::enterRaffle` function : 

``` javascript
for (uint256 i = 0; i < players.length - 1; i++) {
          for (uint256 j = i + 1; j < players.length; j++) {
              require(players[i] != players[j], "PuppyRaffle: Duplicate player");
          }
      }
```

<details>

<summary> Proof of code </summary>

Place following test into `PuppleRuffleTest.t.sol`

```javascript
function test_denialOfServices() public {
      uint256 playersNum = 100;
      address[] memory playersAddress = new address[](playersNum);
      for(uint256 i; i<playersNum; i++){
          playersAddress[i] = address(i);
      }
      
      vm.txGasPrice(1);
      uint256 gasStart = gasleft();
      puppyRaffle.enterRaffle{value: entranceFee * playersAddress.length}(playersAddress);
      uint256 gasEnd = gasleft();

      uint256 gasUsedFirst = ((gasStart - gasEnd) * tx.gasprice);

      uint256 playersNumTwo = 100;
      address[] memory playersAddressTwo = new address[](playersNumTwo);
      for(uint256 i; i<playersNumTwo; i++){
          playersAddressTwo[i] = address(i + playersNumTwo);
      }
      
      vm.txGasPrice(1);
      uint256 gasStartTwo = gasleft();
      puppyRaffle.enterRaffle{value: entranceFee * playersAddressTwo.length}(playersAddressTwo);
      uint256 gasEndTwo = gasleft();
      uint256 gasUsedSecond = ((gasStartTwo - gasEndTwo) * tx.gasprice);
      
      console.log("gas used first 100 players ", gasUsedFirst);
      console.log("gas used second 100 players ", gasUsedSecond);

      assert(gasUsedFirst < gasUsedSecond);
  }

```

</details>


**Recommended mitigation**