// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title  ThreatIntelRegistry
 * @notice Stores SHA-256 hashes of off-chain threat intelligence records.
 *         Provides integrity verification via hash comparison.
 */
contract ThreatIntelRegistry {

    // ─── Data Structures ────────────────────────────────────────────────
    struct ThreatIndicator {
        string  indicatorHash;   // SHA-256 of the full off-chain record
        string  indicatorType;   // "ip" | "domain" | "malware_hash"
        string  severity;        // "low" | "medium" | "high" | "critical"
        uint256 timestamp;       // block.timestamp at registration
        address reporter;        // EOA that submitted the transaction
        bool    exists;          // duplicate guard
    }

    // ─── State ───────────────────────────────────────────────────────────
    address public owner;
    uint256 public totalCount;

    mapping(string => ThreatIndicator) private indicators; // indicatorId → record
    string[] private indicatorIds;

    // ─── Events ──────────────────────────────────────────────────────────
    event IndicatorAdded(
        string  indexed indicatorId,
        string          indicatorHash,
        string          indicatorType,
        string          severity,
        address indexed reporter,
        uint256         timestamp
    );

    event IndicatorVerified(
        string  indexed indicatorId,
        bool            isValid,
        address indexed verifier,
        uint256         timestamp
    );

    // ─── Modifiers ───────────────────────────────────────────────────────
    modifier nonEmpty(string memory v) {
        require(bytes(v).length > 0, "ThreatIntelRegistry: empty value");
        _;
    }

    modifier notRegistered(string memory id) {
        require(!indicators[id].exists, "ThreatIntelRegistry: already registered");
        _;
    }

    modifier isRegistered(string memory id) {
        require(indicators[id].exists, "ThreatIntelRegistry: not found");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────
    constructor() {
        owner      = msg.sender;
        totalCount = 0;
    }

    // ─── Write ───────────────────────────────────────────────────────────

    /**
     * @notice Register a new threat indicator hash on-chain.
     * @param indicatorId   UUID from the off-chain database
     * @param indicatorHash SHA-256 hash of the full indicator record
     * @param indicatorType "ip" | "domain" | "malware_hash"
     * @param severity      "low" | "medium" | "high" | "critical"
     */
    function addThreatIndicator(
        string memory indicatorId,
        string memory indicatorHash,
        string memory indicatorType,
        string memory severity
    )
        external
        nonEmpty(indicatorId)
        nonEmpty(indicatorHash)
        nonEmpty(indicatorType)
        notRegistered(indicatorId)
    {
        indicators[indicatorId] = ThreatIndicator({
            indicatorHash : indicatorHash,
            indicatorType : indicatorType,
            severity      : severity,
            timestamp     : block.timestamp,
            reporter      : msg.sender,
            exists        : true
        });

        indicatorIds.push(indicatorId);
        totalCount++;

        emit IndicatorAdded(
            indicatorId,
            indicatorHash,
            indicatorType,
            severity,
            msg.sender,
            block.timestamp
        );
    }

    /**
     * @notice On-chain hash verification — emits audit event.
     * @return isValid True when the provided hash matches the stored hash.
     */
    function verifyIndicator(
        string memory indicatorId,
        string memory hashToVerify
    )
        external
        isRegistered(indicatorId)
        returns (bool isValid)
    {
        isValid = keccak256(bytes(indicators[indicatorId].indicatorHash))
               == keccak256(bytes(hashToVerify));

        emit IndicatorVerified(indicatorId, isValid, msg.sender, block.timestamp);
    }

    // ─── Read (view / pure — no gas on call) ─────────────────────────────

    /// @notice Returns full metadata for one indicator.
    function getIndicator(string memory indicatorId)
        external
        view
        isRegistered(indicatorId)
        returns (
            string  memory indicatorHash,
            string  memory indicatorType,
            string  memory severity,
            uint256        timestamp,
            address        reporter
        )
    {
        ThreatIndicator storage ind = indicators[indicatorId];
        return (ind.indicatorHash, ind.indicatorType, ind.severity, ind.timestamp, ind.reporter);
    }

    /// @notice Returns true when an indicator ID has been registered.
    function indicatorExists(string memory indicatorId) external view returns (bool) {
        return indicators[indicatorId].exists;
    }

    /// @notice Paginated list of registered indicator IDs (max 50 per page).
    function getIndicatorIds(uint256 offset, uint256 limit)
        external
        view
        returns (string[] memory page)
    {
        if (limit > 50) limit = 50;
        uint256 end = offset + limit;
        if (end > indicatorIds.length) end = indicatorIds.length;
        if (offset >= indicatorIds.length) return new string[](0);

        page = new string[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = indicatorIds[i];
        }
    }
}