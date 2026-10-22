// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SecureVault
/// @notice Sample contract that should produce no High or Medium findings.
/// @dev Used as the negative case in the SmartGuard AI test suite.
///      Written without external imports so it compiles standalone.
contract SecureVault {
    mapping(address => uint256) private _balances;
    address public owner;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        _balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @dev Checks-effects-interactions ordering: state is updated first.
    function withdraw(uint256 amount) external {
        require(_balances[msg.sender] >= amount, "insufficient balance");

        _balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function sweep() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
