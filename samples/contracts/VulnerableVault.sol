// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title VulnerableVault
/// @notice Sample contract used to demonstrate SmartGuard AI Module 2.
/// @dev Contains one High impact and several Medium/Low impact issues.
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev Reentrancy: state is updated after the external call.
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    /// @dev High impact: controlled delegatecall to an arbitrary target.
    function unsafeDelegate(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    /// @dev Medium impact: arbitrary send of contract-held ether.
    function unsafeSend(address payable to) external {
        to.send(address(this).balance);
    }

    /// @dev Informational: unused state variable.
    uint256 public unusedCounter;

    function drain() external {
        payable(owner).transfer(address(this).balance);
    }
}
