// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.17;

import "@gnosis.pm/zodiac/contracts/factory/FactoryFriendly.sol";
import "@gnosis.pm/zodiac/contracts/guard/BaseGuard.sol";

interface IApplicationRegistry {
    function applications(uint96)
        external
        view
        returns (
            uint96,
            uint96,
            address,
            address,
            uint48,
            uint48,
            string memory,
            uint96
        );

    function eoaToScw(bytes32, address) external view returns (address);
}


interface IApplicationReviewRegistry {
    function reviews(address, uint96)
        external
        view
        returns (
            uint96,
            uint96,
            uint96,
            address,
            address,
            string memory,
            bool
        );
}


interface IWorkspaceRegistry {
    function eoaToScw(address, uint96) external view returns (address);
}


contract ReviewerTransactionGuard is BaseGuard {
    fallback() external {
        // We don't revert on fallback to avoid issues in case of a Safe upgrade
        // E.g. The expected check method might change and then the Safe would be locked.
    }

    modifier onlySafe() {
        require(msg.sender == safeAddress, "Unauthorised: Not the Safe");
        _;
    }

    IApplicationRegistry public applicationReg;
    IApplicationReviewRegistry public applicationReviewReg;
    IWorkspaceRegistry public workspaceReg;

    address public safeAddress;
    address[] public reviewers;
    uint96 public threshold;
    bytes4 public constant removeGuardBytesData = hex"e19a9dd9";
    bytes4 public constant multiSendBytesData = hex"8d80ff0a";

    // bytes4 public constant ENCODED_SIG_SET_GUARD = bytes4(keccak256("setGuard(address)")); // hex"e19a9dd9"
    // bytes4 public constant ENCODED_SIG_MULTI_SEND = bytes4(keccak256("")); // hex"8d80ff0a"

    constructor(
        address _safeAddress,
        address[] memory _reviewers,
        uint96 _threshold,
        IApplicationRegistry _applicationReg,
        IApplicationReviewRegistry _applicationReviewReg,
        IWorkspaceRegistry _workspaceReg
    ) {
        require(
            _reviewers.length >= _threshold,
            "Threshold can't be greater than the number of reviewers"
        );
        safeAddress = _safeAddress;
        reviewers = _reviewers;
        threshold = _threshold;

        applicationReg = _applicationReg;
        applicationReviewReg = _applicationReviewReg;
        workspaceReg = _workspaceReg;
    }

    function setWorkspaceReg(IWorkspaceRegistry _workspaceReg) 
        external 
        onlySafe 
    {
        workspaceReg = _workspaceReg;
    }

    function setApplicationReg(IApplicationRegistry _applicationReg) 
        external 
        onlySafe 
    {
        applicationReg = _applicationReg;
    }

    function setApplicationReviewReg(IApplicationReviewRegistry _applicationReviewReg) 
        external 
        onlySafe 
    {
        applicationReviewReg = _applicationReviewReg;
    }

    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external override {
        require(
            getFunctionSelector(data) != removeGuardBytesData,
            "This guard cannot be removed or changed!"
        );
        // require(bytes4(data) != ENCODED_SIG_SET_GUARD, "This guard cannot be removed or changed!");

        // Allows policy changes and rejections
        if (to != safeAddress && to != address(this)) {
            uint96 appId;
            uint96 workspaceId;
            address grantAddress;
            address applicantAddress;

            if (getFunctionSelector(data) == multiSendBytesData) {
                uint96 numTransfers = getId(data, 68) / 281;

                for (uint96 i = 0; i < numTransfers; i++) {
                    workspaceId = getId(data, 32 + 221 + (i * 281));
                    grantAddress = getAddress(data, 32 + 253 + (i * 281));
                    appId = getId(data, 32 + 285 + (i * 281));
                    applicantAddress = getAddress(
                        data,
                        32 + 157 + (i * 281)
                    );

                    fetchReviews(workspaceId, appId, grantAddress, applicantAddress);
                }
            } else {
                workspaceId = getId(data, 100);
                grantAddress = getAddress(data, 132);
                appId = getId(data, 164);
                applicantAddress = getAddress(data, 36);

                fetchReviews(workspaceId, appId, grantAddress, applicantAddress);
            }
        }
    }

    function checkAfterExecution(bytes32 txHash, bool success)
        external
        override
    {}

    function fetchReviews(uint96 _workspaceId, uint96 _appId, address grantAddress, address _applicantPaymentAddress)
        public
        view
    {
        address applicantWalletAddress;
        (, , , applicantWalletAddress, , , , ) = applicationReg.applications(
            _appId
        );
        address applicantZerowalletAddress = applicationReg
            .eoaToScw(bytes32(uint256(uint160(_applicantPaymentAddress))), grantAddress);

        require(
            applicantZerowalletAddress == applicantWalletAddress,
            "The proposal author, application and payment address have a mismatch"
        );

        uint96 k = 0;

        for (uint96 i = 0; i < reviewers.length; i++) {
            string memory metadataHash;
            address zerowalletAddress = workspaceReg.eoaToScw(
                reviewers[i],
                _workspaceId
            );
            (, , , , , metadataHash, ) = applicationReviewReg.reviews(
                zerowalletAddress,
                _appId
            );
            if (bytes(metadataHash).length != 0) {
                ++k;
            }
        }

        require(
            k >= threshold,
            "The threshold to take a decision on this application has not been reached yet!"
        );
    }

    function addReviewer(address _address) external onlySafe {
        reviewers.push(_address);
    }

    function removeReviewer(address _address) external onlySafe {
        for (uint96 i = 0; i < reviewers.length; i++) {
            if (reviewers[i] == _address) {
                reviewers[i] = reviewers[reviewers.length - 1];
                reviewers.pop();
                break;
            }
        }
    }

    function updateThreshold(uint96 _threshold) external onlySafe {
        threshold = _threshold;
    }

    function getId(bytes memory data, uint256 offset)
        internal
        pure
        returns (uint96 appId)
    {
        assembly {
            appId := mload(add(data, offset))
        }
    }

    function getFunctionSelector(bytes memory data)
        internal
        pure
        returns (bytes4 sel)
    {
        assembly {
            sel := mload(add(data, 32))
        }
    }

    function getAddress(bytes memory data, uint256 offset)
        internal
        pure
        returns (address addr)
    {
        assembly {
            addr := mload(add(data, offset))
        }
    }

    /// @dev Returns array of reviewers.
    /// @return Array of Guard reviewers.
    function getReviewers() public view returns (address[] memory) {
        address[] memory array = new address[](reviewers.length);

        // populate return array
        for (uint256 i = 0; i < reviewers.length; i++) {
            array[i] = reviewers[i];
        }

        return array;
    }
}

contract ReviewerDeployer {
    uint256 public counter;

    // --- Events ---
    /// @notice Emitted when a new guard is deployed
    event GuardDeployed(
        ReviewerTransactionGuard guardContract,
        address safeAddress,
        address[] reviewers,
        uint96 threshold
    );

    function deploy(
        address _safeAddress,
        address[] memory _reviewers,
        uint96 _threshold,
        IApplicationRegistry _applicationReg,
        IApplicationReviewRegistry _applicationReviewReg,
        IWorkspaceRegistry _workspaceReg
    ) public {
        ReviewerTransactionGuard guardContract = new ReviewerTransactionGuard(
            _safeAddress,
            _reviewers,
            _threshold,
            _applicationReg,
            _applicationReviewReg,
            _workspaceReg
        );
        
        ++counter;

        emit GuardDeployed(
            guardContract,
            _safeAddress,
            _reviewers,
            _threshold
        );
    }
}
