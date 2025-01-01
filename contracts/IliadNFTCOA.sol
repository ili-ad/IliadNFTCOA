// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";


/**
 * @title IliadNFTCOA
 * @dev ERC721 Token with governance and metadata management.
 */
contract IliadNFTCOA is ERC721URIStorage, AccessControl {
    // Define roles using keccak256 hash
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    bytes32 public constant METADATA_MANAGER_ROLE = keccak256("METADATA_MANAGER_ROLE");

    /**
     * @dev Structure to store proposal details.
     */
    struct Proposal {
        string action;
        uint256 tokenId;
        bytes params;
        uint8 approvals; // Optimized for gas
        bool active;
        uint256 createdAt; // Timestamp of creation
    }

    // Mapping from proposal hash to Proposal details
    mapping(bytes32 => Proposal) private proposals;

    // Mapping from proposal hash to approvers
    mapping(bytes32 => mapping(address => bool)) private proposalApprovers;

    // Mapping to track last proposal time per proposer
    mapping(address => uint256) private lastProposalTime;

    // Mapping for quorum thresholds per action
    mapping(string => uint256) public quorumThresholds;

    // Mapping for action-specific expiry durations
    mapping(string => uint256) private actionExpiryDurations;

    // Mapping to track used serial hashes to ensure uniqueness
    mapping(bytes32 => bool) private usedSerialHashes;

    // Mapping to track metadata lock status per token
    mapping(uint256 => bool) private tokenMetadataLocked;

    // Total number of minted tokens
    uint256 private totalMinted;

    // Base URI for token metadata
    string private baseURI;

    // Default expiry duration for proposals
    uint256 public defaultExpiry = 7 days;

    // Events for governance and token management
    event ProposalCreated(bytes32 indexed actionHash, string action, address proposer);
    event ProposalApproved(bytes32 indexed actionHash, address approver);
    event ProposalRevoked(bytes32 indexed actionHash, address revoker);
    event ProposalExecuted(bytes32 indexed actionHash, string action);
    event ProposalExpired(bytes32 indexed actionHash);
    event ProposalReactivated(bytes32 indexed actionHash, address reactivator);
    event ProposalArchived(bytes32 indexed actionHash);
    event TokenMetadataLocked(uint256 indexed tokenId);
    event TokenMetadataUnlocked(uint256 indexed tokenId);
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event TokenMinted(address indexed to, uint256 tokenId, string serial);
    event TokenBurned(uint256 indexed tokenId, address indexed burnedBy);
    event TokenForceTransferred(uint256 indexed tokenId, address indexed from, address indexed to);
    event BaseURISet(string newBaseURI);
    event BaseURIUpdated(string oldBaseURI, string newBaseURI);

    /**
     * @dev Constructor to initialize the contract with base URI and set up roles.
     * Also initializes quorum thresholds for supported actions.
     * @param _baseURI The base URI for token metadata.
     */
    constructor(string memory _baseURI) ERC721("IliadNFTCOA", "FDCO") {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(PROPOSER_ROLE, msg.sender);
        _setupRole(APPROVER_ROLE, msg.sender);
        _setupRole(METADATA_MANAGER_ROLE, msg.sender);

        _setBaseURI(_baseURI); // Initialize baseURI via internal function

        // Initialize quorum thresholds for supported actions
        quorumThresholds["burnAndReissue"] = 2; // Example: Requires 2 approvals
        quorumThresholds["forceTransfer"] = 2;  // Example: Requires 2 approvals
    }

    // function _exists(uint256 tokenId) internal view override(ERC721) returns (bool) {
    //     return super._exists(tokenId);
    // }


    /**
     * @notice Mint a new token with a unique serial number.
     * @dev Only accounts with MINTER_ROLE can call this function.
     * @param to The address to receive the newly minted token.
     * @param serial A 6-character serial string, unique for each token.
     */
    function mint(address to, string memory serial) public onlyRole(MINTER_ROLE) {
        require(bytes(serial).length == 6, "Serial must be exactly 6 characters.");
        bytes32 serialHash = keccak256(abi.encodePacked(serial));
        require(!usedSerialHashes[serialHash], "Serial already used.");
        usedSerialHashes[serialHash] = true;

        uint256 tokenId = totalMinted + 1;
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, constructTokenURI(serial));
        totalMinted++;

        emit TokenMinted(to, tokenId, serial);
    }

    /**
     * @notice Create a governance proposal for an action.
     * @dev The caller must wait 1 day between proposals.
     * @param action The action name (e.g., "burnAndReissue", "forceTransfer").
     * @param tokenId The tokenId to which the action applies (if applicable).
     * @param params Encoded parameters for the action.
     * @param customExpiry Optional custom expiry duration in seconds. If zero, defaultExpiry is used.
     */
    function proposeAction(
        string memory action,
        uint256 tokenId,
        bytes memory params,
        uint256 customExpiry
    ) public onlyRole(PROPOSER_ROLE) {
        require(
            block.timestamp >= lastProposalTime[msg.sender] + 1 days,
            "Must wait before creating another proposal."
        );
        bytes32 actionHash = keccak256(abi.encodePacked(action, tokenId, params));
        require(!proposals[actionHash].active, "Cannot overwrite an active proposal.");

        proposals[actionHash] = Proposal({
            action: action,
            tokenId: tokenId,
            params: params,
            approvals: 1,
            active: true,
            createdAt: block.timestamp
        });
        proposalApprovers[actionHash][msg.sender] = true;
        lastProposalTime[msg.sender] = block.timestamp;

        // Set custom expiry if provided
        if (customExpiry > 0) {
            actionExpiryDurations[action] = customExpiry;
        }

        emit ProposalCreated(actionHash, action, msg.sender);
    }

    /**
     * @notice Approve a governance proposal.
     * @dev Automatically handles expired proposals by cleaning them up.
     * @param actionHash The hash of the proposal to approve.
     */
    function approveProposal(bytes32 actionHash) public onlyRole(APPROVER_ROLE) {
        Proposal storage proposal = proposals[actionHash];
        require(proposal.active, "Proposal is not active.");

        // Check if the proposal has expired
        if (block.timestamp >= proposal.createdAt + getActionExpiry(proposal.action)) {
            // Clean up the expired proposal
            proposal.active = false;
            resetProposal(actionHash);
            emit ProposalExpired(actionHash);
            return;
        }

        require(
            !proposalApprovers[actionHash][msg.sender],
            "Cannot approve proposal more than once."
        );
        proposal.approvals++;
        proposalApprovers[actionHash][msg.sender] = true;

        emit ProposalApproved(actionHash, msg.sender);

        if (isQuorumReached(actionHash)) {
            executeAction(actionHash);
        }
    }

    /**
     * @notice Revoke an approval for a governance proposal.
     * @dev Only approvers who have previously approved can revoke their approval.
     * @param actionHash The hash of the proposal to revoke approval from.
     */
    function revokeApproval(bytes32 actionHash) public onlyRole(APPROVER_ROLE) {
        Proposal storage proposal = proposals[actionHash];
        require(proposal.active, "Proposal is not active.");
        require(
            proposalApprovers[actionHash][msg.sender],
            "You have not approved this proposal."
        );

        proposal.approvals--;
        proposalApprovers[actionHash][msg.sender] = false;

        emit ProposalRevoked(actionHash, msg.sender);
    }

    /**
     * @notice Reactivate an expired proposal.
     * @dev The proposal must have expired to be reactivated. Requires re-approval.
     * @param actionHash The hash of the proposal to reactivate.
     */
    function reactivateProposal(bytes32 actionHash) public onlyRole(PROPOSER_ROLE) {
        Proposal storage proposal = proposals[actionHash];
        require(!proposal.active, "Proposal is still active.");
        require(
            block.timestamp >= proposal.createdAt + getActionExpiry(proposal.action),
            "Proposal has not yet expired."
        );

        // Reset approvals
        proposal.approvals = 0;
        // Reactivation requires re-approvals
        // Only the proposer reactivates and their approval is counted
        proposal.active = true;
        proposal.createdAt = block.timestamp;
        proposal.approvals = 1;
        proposalApprovers[actionHash][msg.sender] = true;
        lastProposalTime[msg.sender] = block.timestamp;

        emit ProposalReactivated(actionHash, msg.sender);
    }

    /**
     * @notice Archive a stale proposal.
     * @dev Only APPROVER_ROLE can archive inactive proposals.
     * @param actionHash The hash of the proposal to archive.
     */
    function archiveProposal(bytes32 actionHash) public onlyRole(APPROVER_ROLE) {
        Proposal storage proposal = proposals[actionHash];
        require(!proposal.active, "Cannot archive an active proposal.");
        resetProposal(actionHash);
        emit ProposalArchived(actionHash);
    }

    /**
     * @notice Clean up a previously expired (and inactive) proposal.
     * @dev Only APPROVER_ROLE can call this function.
     * @param actionHash The hash of the proposal to clean.
     */
    function cleanUpProposal(bytes32 actionHash) public onlyRole(APPROVER_ROLE) {
        require(!isProposalActive(actionHash), "Proposal is still active.");
        resetProposal(actionHash);
        emit ProposalExpired(actionHash);
    }

    /**
     * @dev Execute a governance action based on the proposal.
     * @param actionHash The hash of the proposal to execute.
     */
    function executeAction(bytes32 actionHash) internal {
        Proposal storage proposal = proposals[actionHash];
        require(proposal.active, "Proposal is not active.");
        proposal.active = false;

        if (keccak256(bytes(proposal.action)) == keccak256("burnAndReissue")) {
            (address newOwner, string memory newSerial) = abi.decode(
                proposal.params,
                (address, string)
            );
            burnAndReissue(proposal.tokenId, newOwner, newSerial);
        } else if (
            keccak256(bytes(proposal.action)) == keccak256("forceTransfer")
        ) {
            address newOwner = abi.decode(proposal.params, (address));
            forceTransfer(proposal.tokenId, newOwner);
        } else {
            revert("Unsupported proposal action.");
        }

        resetProposal(actionHash);
        emit ProposalExecuted(actionHash, proposal.action);
    }

    /**
     * @notice Burn and optionally reissue a token.
     * @dev Only called internally upon proposal execution.
     * @param tokenId The ID of the token to burn.
     * @param newOwner The address to receive the reissued token.
     * @param newSerial The new serial number for the reissued token.
     */
    function burnAndReissue(
        uint256 tokenId,
        address newOwner,
        string memory newSerial
    ) internal {
        require(_exists(tokenId), "Token does not exist.");
        address currentOwner = ownerOf(tokenId);

        _burn(tokenId);
        emit TokenBurned(tokenId, currentOwner);

        if (bytes(newSerial).length > 0) {
            bytes32 serialHash = keccak256(abi.encodePacked(newSerial));
            require(!usedSerialHashes[serialHash], "New serial already used.");
            usedSerialHashes[serialHash] = true;

            uint256 newTokenId = totalMinted + 1;
            _safeMint(newOwner, newTokenId);
            _setTokenURI(newTokenId, constructTokenURI(newSerial));
            totalMinted++;

            emit TokenMinted(newOwner, newTokenId, newSerial);
        }
    }

    /**
     * @notice Force transfer a token to a new owner.
     * @dev Only called internally upon proposal execution.
     * @param tokenId The ID of the token to transfer.
     * @param newOwner The address to receive the token.
     */
    function forceTransfer(uint256 tokenId, address newOwner) internal {
        require(_exists(tokenId), "Token does not exist.");
        address currentOwner = ownerOf(tokenId);
        require(currentOwner != newOwner, "Cannot transfer to current owner.");

        _transfer(currentOwner, newOwner, tokenId);
        emit TokenForceTransferred(tokenId, currentOwner, newOwner);
    }

    /**
     * @notice Lock metadata for a token to prevent further modifications.
     * @dev Only accounts with METADATA_MANAGER_ROLE can call this function.
     * @param tokenId The ID of the token to lock metadata for.
     */
    function lockMetadata(uint256 tokenId)
        public
        onlyRole(METADATA_MANAGER_ROLE)
    {
        require(_exists(tokenId), "Token does not exist.");
        require(!tokenMetadataLocked[tokenId], "Metadata is already locked.");
        tokenMetadataLocked[tokenId] = true;
        emit TokenMetadataLocked(tokenId);
    }

    /**
     * @notice Unlock metadata for a token to allow modifications.
     * @dev Only accounts with DEFAULT_ADMIN_ROLE can call this function.
     * @param tokenId The ID of the token to unlock metadata for.
     */
    function unlockMetadata(uint256 tokenId)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_exists(tokenId), "Token does not exist.");
        require(tokenMetadataLocked[tokenId], "Metadata is already unlocked.");
        tokenMetadataLocked[tokenId] = false;
        emit TokenMetadataUnlocked(tokenId);
    }

    /**
     * @notice Check if metadata is locked for a given token.
     * @param tokenId The token ID to check.
     * @return True if metadata is locked, false otherwise.
     */
    function isMetadataLocked(uint256 tokenId)
        public
        view
        returns (bool)
    {
        return tokenMetadataLocked[tokenId];
    }

    /**
     * @notice Set a custom expiry duration for a specific action.
     * @dev Only accounts with DEFAULT_ADMIN_ROLE can call this function.
     * @param action The action name.
     * @param duration The new expiry duration in seconds.
     */
    function setActionExpiry(string memory action, uint256 duration)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(duration > 0, "Duration must be greater than zero.");
        actionExpiryDurations[action] = duration;
    }

    /**
     * @notice Get the expiry duration for a given action.
     * @param action The action name.
     * @return The expiry duration in seconds.
     */
    function getActionExpiry(string memory action)
        public
        view
        returns (uint256)
    {
        uint256 duration = actionExpiryDurations[action];
        return duration > 0 ? duration : defaultExpiry;
    }

    /**
     * @dev Check if a quorum has been reached for a proposal.
     * @param actionHash The hash of the proposal.
     * @return True if quorum is reached, false otherwise.
     */
    function isQuorumReached(bytes32 actionHash)
        internal
        view
        returns (bool)
    {
        Proposal storage proposal = proposals[actionHash];
        uint256 requiredQuorum = quorumThresholds[proposal.action];
        return proposal.approvals >= requiredQuorum;
    }

    /**
     * @dev Reset a proposal by deleting it from storage.
     * @param actionHash The hash of the proposal to reset.
     */
    function resetProposal(bytes32 actionHash) internal {
        delete proposals[actionHash];
    }

    /**
     * @notice Construct a token URI from base URI and serial.
     * @param serial The token's serial string.
     * @return The fully constructed token URI.
     */
    function constructTokenURI(string memory serial)
        public
        view
        returns (string memory)
    {
        return string(abi.encodePacked(baseURI, serial));
    }

    /**
     * @notice Check if a proposal is currently active and not expired.
     * @param actionHash The hash of the proposal.
     * @return True if active and within expiry period, false otherwise.
     */
    function isProposalActive(bytes32 actionHash)
        public
        view
        returns (bool)
    {
        Proposal storage proposal = proposals[actionHash];
        return
            proposal.active &&
            block.timestamp < proposal.createdAt + getActionExpiry(proposal.action);
    }

    /**
     * @notice Get the textual status of a proposal.
     * @param actionHash The hash of the proposal.
     * @return "Active", "Expired", or "Inactive".
     */
    function getProposalStatus(bytes32 actionHash)
        public
        view
        returns (string memory)
    {
        Proposal storage proposal = proposals[actionHash];
        if (!proposal.active) return "Inactive";
        if (
            block.timestamp >=
            proposal.createdAt + getActionExpiry(proposal.action)
        ) return "Expired";
        return "Active";
    }

    /**
    * @notice Override the supportsInterface to resolve multiple inheritance.
    * @dev Overrides both ERC721URIStorage and AccessControl implementations.
    * @param interfaceId The interface identifier, as specified in ERC-165.
    * @return True if the contract implements `interfaceId`.
    */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721URIStorage, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }


    /**
    * @notice Override the _beforeTokenTransfer to match the base class signature.
    * @dev Overrides ERC721's _beforeTokenTransfer function.
    * @param from The address transferring the token.
    * @param to The address receiving the token.
    * @param tokenId The ID of the token being transferred.
    * @param batchSize The number of tokens being transferred.
    */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId,
        uint256 batchSize
    ) internal virtual override(ERC721) {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
        // Additional logic can be added here
    }

    /**
     * @notice Override the _setTokenURI to include metadata lock check.
     * @dev Prevents setting token URI if metadata is locked.
     * @param tokenId The ID of the token.
     * @param _tokenURI The new token URI to set.
     */
    function _setTokenURI(uint256 tokenId, string memory _tokenURI)
        internal
        override
    {
        require(
            !tokenMetadataLocked[tokenId],
            "Cannot modify metadata: Metadata is locked."
        );
        super._setTokenURI(tokenId, _tokenURI);
    }

    /**
     * @notice Get the base URI set for the contract.
     * @dev Since baseURI is not exposed directly, this function can be used if needed.
     * @return The base URI string.
     */
    function getBaseURI() public view returns (string memory) {
        return baseURI;
    }

    /**
     * @notice Set a new base URI for the contract.
     * @dev Only accounts with DEFAULT_ADMIN_ROLE can call this function.
     * Ensures the new base URI ends with a trailing slash.
     * @param _newBaseURI The new base URI to set.
     */
    function setBaseURI(string memory _newBaseURI)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(
            bytes(_newBaseURI).length > 0,
            "Base URI cannot be empty."
        );
        require(
            bytes(_newBaseURI)[bytes(_newBaseURI).length - 1] == bytes1("/"),
            "Base URI must end with a trailing slash."
        );
        string memory oldBaseURI = baseURI;
        _setBaseURI(_newBaseURI);
        emit BaseURIUpdated(oldBaseURI, _newBaseURI);
    }

    /**
     * @dev Internal function to set the base URI.
     * @param _newBaseURI The new base URI to set.
     */
    function _setBaseURI(string memory _newBaseURI) internal {
        require(
            bytes(_newBaseURI).length > 0,
            "Base URI cannot be empty."
        );
        require(
            bytes(_newBaseURI)[bytes(_newBaseURI).length - 1] == bytes1("/"),
            "Base URI must end with a trailing slash."
        );
        baseURI = _newBaseURI;
        emit BaseURISet(_newBaseURI);
    }

    /**
     * @notice Add a new quorum threshold for a specific action.
     * @dev Only accounts with DEFAULT_ADMIN_ROLE can call this function.
     * @param action The action name.
     * @param threshold The quorum threshold required for the action.
     */
    function addQuorumThreshold(string memory action, uint256 threshold)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(threshold > 0, "Quorum threshold must be greater than zero.");
        quorumThresholds[action] = threshold;
    }

    /**
     * @notice Remove a quorum threshold for a specific action.
     * @dev Only accounts with DEFAULT_ADMIN_ROLE can call this function.
     * @param action The action name.
     */
    function removeQuorumThreshold(string memory action)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(
            quorumThresholds[action] > 0,
            "Quorum threshold does not exist for this action."
        );
        delete quorumThresholds[action];
    }

    /**
     * @notice Get the total number of minted tokens.
     * @return The total minted tokens count.
     */
    function getTotalMinted() public view returns (uint256) {
        return totalMinted;
    }

    /**
     * @notice Get details of a specific proposal.
     * @param actionHash The hash of the proposal.
     * @return The Proposal struct containing all details.
     */
    function getProposalDetails(bytes32 actionHash)
        public
        view
        returns (Proposal memory)
    {
        return proposals[actionHash];
    }
}
