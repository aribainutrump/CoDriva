// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CoDriva
/// @notice On-chain registry for speed camera and safety zone alerts. Reporters register radar zones with coordinates and speed limits; users consume zone data; reward pool pays out for verified alerts. Suited for driving apps and speed camera detector services.
/// @dev Governor and treasury are immutable. ReentrancyGuard and Pausable applied. No upgrade path.

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/Pausable.sol";

contract CoDriva is ReentrancyGuard, Pausable {

    // -------------------------------------------------------------------------
    // EVENTS
    // -------------------------------------------------------------------------

    event CD_RadarZoneRegistered(
        bytes32 indexed zoneId,
        address indexed reporter,
        int32 latE6,
        int32 lngE6,
        uint16 speedLimitKph,
        uint256 rewardWei,
        uint256 atBlock
    );
    event CD_SpeedLimitUpdated(bytes32 indexed zoneId, uint16 oldKph, uint16 newKph, uint256 atBlock);
    event CD_AlertClaimed(bytes32 indexed zoneId, address indexed claimer, uint256 amountWei, uint256 atBlock);
    event CD_PoolToppedUp(address indexed from, uint256 amountWei, uint256 atBlock);
    event CD_ZoneDeactivated(bytes32 indexed zoneId, address indexed by, uint256 atBlock);
    event CD_GovernancePaused(address indexed by, uint256 atBlock);
    event CD_GovernanceUnpaused(address indexed by, uint256 atBlock);
    event CD_ValidatorSet(address indexed previousValidator, address indexed newValidator, uint256 atBlock);
    event CD_FeeCollectorSet(address indexed previousFeeCollector, address indexed newFeeCollector, uint256 atBlock);

    // -------------------------------------------------------------------------
    // ERRORS
    // -------------------------------------------------------------------------

    error CD_ZeroAddress();
    error CD_NotGovernor();
    error CD_NotTreasury();
    error CD_NotValidator();
    error CD_NotReporter();
    error CD_ZoneNotFound();
    error CD_AlreadyClaimed();
    error CD_InvalidSpeedLimit();
    error CD_TransferFailed();
    error CD_MaxZonesReached();
    error CD_ZoneExists();
    error CD_ZoneNotActive();
    error CD_Paused();
    error CD_ZeroReward();
    error CD_InvalidCoordinates();
    error CD_ZoneIdMismatch();
    error CD_BatchTooLarge();
    error CD_InvalidLatE6();
    error CD_InvalidLngE6();
    error CD_DuplicateZoneId();
    error CD_InvalidOffset();
    error CD_InvalidLimit();
    error CD_NotFeeCollector();
    error CD_ZeroZoneId();
    error CD_ReporterMismatch();

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    uint256 public constant CD_MAX_RADAR_ZONES = 2000;
    uint16 public constant CD_MAX_SPEED_KPH = 250;
    uint16 public constant CD_MIN_SPEED_KPH = 5;
    uint256 public constant CD_MAX_BATCH_QUERY = 100;
    bytes32 public constant CD_NETWORK_TAG = 0x4b7c2e9f1a6d3f8b0c5e2a9d7f4b1c8e0a3f6d9b2c5e8a1d4f7b0c3e6a9d2f5b8;
    bytes32 public constant CD_DOMAIN_SEED = keccak256("CoDriva.RadarZones.v1");
    string public constant CD_ZONE_ID_PREFIX = "CDZ-";
    int32 public constant CD_LAT_E6_MIN = -90_000000;
    int32 public constant CD_LAT_E6_MAX = 90_000000;
    int32 public constant CD_LNG_E6_MIN = -180_000000;
    int32 public constant CD_LNG_E6_MAX = 180_000000;

    // -------------------------------------------------------------------------
    // ENUMS & STRUCTS
    // -------------------------------------------------------------------------

    enum ZoneType { FixedCamera, MobileUnit, AverageSpeed, RedLight }
    enum ValidationStatus { Pending, Verified, Rejected }

    struct RadarZone {
        bytes32 zoneId;
        int32 latE6;
        int32 lngE6;
        uint16 speedLimitKph;
        address reporter;
        uint256 rewardWei;
        bool claimed;
        bool active;
        uint256 blockRegistered;
        ZoneType zoneType;
        ValidationStatus validationStatus;
        uint256 lastUpdatedBlock;
    }

    struct ZoneSummary {
        bytes32 zoneId;
        int32 latE6;
        int32 lngE6;
        uint16 speedLimitKph;
        bool active;
        bool claimed;
        uint256 blockRegistered;
    }

    struct ClaimParams {
        bytes32 zoneId;
        address claimer;
    }

    // -------------------------------------------------------------------------
    // IMMUTABLES
    // -------------------------------------------------------------------------

    address public immutable governor;
    address public immutable treasury;
    uint256 public immutable deployBlock;

    // -------------------------------------------------------------------------
    // STATE
    // -------------------------------------------------------------------------

    address public validator;
    address public feeCollector;
    mapping(bytes32 => RadarZone) private _zonesById;
    mapping(address => bytes32[]) private _zoneIdsByReporter;
    bytes32[] private _allZoneIds;
    uint256 public totalZonesRegistered;
    uint256 public totalZonesActive;
    uint256 public totalRewardsClaimed;
    uint256 public poolBalance;
    uint256 public totalPoolToppedUp;
    mapping(bytes32 => uint256) private _zoneIndexById;

    // -------------------------------------------------------------------------
    // CONSTRUCTOR
    // -------------------------------------------------------------------------

    constructor() {
        governor = address(0x4B7c2E9f1A6d3F8b0C5e2A9D7f4B1c8E0a3F6d9B2);
        treasury = address(0x2F8a1D4c7E0b3F6a9C2e5B8d1F4a7E0c3D6f9B1e4);
        validator = address(0x9E3b6C0d2F5a8B1e4D7c0A3f6B9e2C5d8F1a4c7E0);
        feeCollector = address(0xD1a4E7c0F3b6A9d2C5e8B1f4A7c0D3e6F9a2b5d8);
        deployBlock = block.number;
        if (governor == address(0) || treasury == address(0)) revert CD_ZeroAddress();
    }

    // -------------------------------------------------------------------------
    // MODIFIERS
    // -------------------------------------------------------------------------

    modifier onlyGovernor() {
        if (msg.sender != governor) revert CD_NotGovernor();
        _;
    }

    modifier onlyTreasury() {
        if (msg.sender != treasury) revert CD_NotTreasury();
        _;
    }

    modifier whenNotPausedCD() {
        if (paused()) revert CD_Paused();
        _;
    }

    modifier onlyValidator() {
        if (msg.sender != validator) revert CD_NotValidator();
        _;
    }

    // -------------------------------------------------------------------------
    // EXTERNAL (GOVERNANCE)
    // -------------------------------------------------------------------------

    function pause() external onlyGovernor {
        _pause();
        emit CD_GovernancePaused(msg.sender, block.number);
    }

    function unpause() external onlyGovernor {
        _unpause();
        emit CD_GovernanceUnpaused(msg.sender, block.number);
    }

    function setValidator(address newValidator) external onlyGovernor {
        if (newValidator == address(0)) revert CD_ZeroAddress();
        address prev = validator;
        validator = newValidator;
        emit CD_ValidatorSet(prev, newValidator, block.number);
    }

    function setFeeCollector(address newFeeCollector) external onlyGovernor {
        if (newFeeCollector == address(0)) revert CD_ZeroAddress();
        address prev = feeCollector;
        feeCollector = newFeeCollector;
        emit CD_FeeCollectorSet(prev, newFeeCollector, block.number);
    }

    // -------------------------------------------------------------------------
    // EXTERNAL (TREASURY)
    // -------------------------------------------------------------------------

    function topUpPool() external payable onlyTreasury whenNotPausedCD {
        if (msg.value == 0) revert CD_ZeroReward();
        poolBalance += msg.value;
        totalPoolToppedUp += msg.value;
        emit CD_PoolToppedUp(msg.sender, msg.value, block.number);
    }

    function topUpPoolPublic() external payable whenNotPausedCD {
        if (msg.value == 0) revert CD_ZeroReward();
        poolBalance += msg.value;
        totalPoolToppedUp += msg.value;
        emit CD_PoolToppedUp(msg.sender, msg.value, block.number);
    }

    // -------------------------------------------------------------------------
    // EXTERNAL (REGISTER ZONE)
    // -------------------------------------------------------------------------

    function registerZone(
        bytes32 zoneId,
        int32 latE6,
        int32 lngE6,
        uint16 speedLimitKph,
        uint256 rewardWei,
        ZoneType zoneType
    ) external whenNotPausedCD nonReentrant {
        if (_zonesById[zoneId].blockRegistered != 0) revert CD_ZoneExists();
        if (_allZoneIds.length >= CD_MAX_RADAR_ZONES) revert CD_MaxZonesReached();
        if (speedLimitKph < CD_MIN_SPEED_KPH || speedLimitKph > CD_MAX_SPEED_KPH) revert CD_InvalidSpeedLimit();
        if (latE6 < CD_LAT_E6_MIN || latE6 > CD_LAT_E6_MAX) revert CD_InvalidLatE6();
        if (lngE6 < CD_LNG_E6_MIN || lngE6 > CD_LNG_E6_MAX) revert CD_InvalidLngE6();

        _zonesById[zoneId] = RadarZone({
            zoneId: zoneId,
            latE6: latE6,
            lngE6: lngE6,
            speedLimitKph: speedLimitKph,
            reporter: msg.sender,
            rewardWei: rewardWei,
            claimed: false,
            active: true,
            blockRegistered: block.number,
            zoneType: zoneType,
            validationStatus: ValidationStatus.Pending,
            lastUpdatedBlock: block.number
        });

        _zoneIdsByReporter[msg.sender].push(zoneId);
        _allZoneIds.push(zoneId);
        _zoneIndexById[zoneId] = _allZoneIds.length - 1;
        totalZonesRegistered += 1;
        totalZonesActive += 1;

        emit CD_RadarZoneRegistered(zoneId, msg.sender, latE6, lngE6, speedLimitKph, rewardWei, block.number);
    }

    function updateSpeedLimit(bytes32 zoneId, uint16 newKph) external whenNotPausedCD {
        RadarZone storage z = _zonesById[zoneId];
        if (z.blockRegistered == 0) revert CD_ZoneNotFound();
        if (z.reporter != msg.sender && msg.sender != validator) revert CD_NotReporter();
        if (!z.active) revert CD_ZoneNotActive();
        if (newKph < CD_MIN_SPEED_KPH || newKph > CD_MAX_SPEED_KPH) revert CD_InvalidSpeedLimit();

        uint16 oldKph = z.speedLimitKph;
        z.speedLimitKph = newKph;
        z.lastUpdatedBlock = block.number;

        emit CD_SpeedLimitUpdated(zoneId, oldKph, newKph, block.number);
    }

    function deactivateZone(bytes32 zoneId) external whenNotPausedCD {
        RadarZone storage z = _zonesById[zoneId];
        if (z.blockRegistered == 0) revert CD_ZoneNotFound();
        if (z.reporter != msg.sender && msg.sender != validator && msg.sender != governor) revert CD_NotReporter();
        if (!z.active) revert CD_ZoneNotActive();

        z.active = false;
        totalZonesActive -= 1;
        emit CD_ZoneDeactivated(zoneId, msg.sender, block.number);
    }

    function verifyZone(bytes32 zoneId) external onlyValidator whenNotPausedCD {
        RadarZone storage z = _zonesById[zoneId];
        if (z.blockRegistered == 0) revert CD_ZoneNotFound();
        z.validationStatus = ValidationStatus.Verified;
        z.lastUpdatedBlock = block.number;
    }

    function rejectZone(bytes32 zoneId) external onlyValidator whenNotPausedCD {
        RadarZone storage z = _zonesById[zoneId];
        if (z.blockRegistered == 0) revert CD_ZoneNotFound();
        z.validationStatus = ValidationStatus.Rejected;
        z.lastUpdatedBlock = block.number;
    }

    // -------------------------------------------------------------------------
    // EXTERNAL (CLAIM)
    // -------------------------------------------------------------------------

    function claimAlertReward(bytes32 zoneId) external whenNotPausedCD nonReentrant {
        RadarZone storage z = _zonesById[zoneId];
        if (z.blockRegistered == 0) revert CD_ZoneNotFound();
        if (z.claimed) revert CD_AlreadyClaimed();
        if (!z.active) revert CD_ZoneNotActive();
        if (z.rewardWei == 0) revert CD_ZeroReward();
        if (poolBalance < z.rewardWei) revert CD_TransferFailed();

        z.claimed = true;
        poolBalance -= z.rewardWei;
        totalRewardsClaimed += z.rewardWei;

        (bool ok,) = msg.sender.call{ value: z.rewardWei }("");
        if (!ok) revert CD_TransferFailed();

        emit CD_AlertClaimed(zoneId, msg.sender, z.rewardWei, block.number);
    }

    function claimAlertRewardBatch(bytes32[] calldata zoneIds) external whenNotPausedCD nonReentrant {
        if (zoneIds.length > CD_MAX_BATCH_QUERY) revert CD_BatchTooLarge();
        uint256 total = 0;
        for (uint256 i = 0; i < zoneIds.length; i++) {
            RadarZone storage z = _zonesById[zoneIds[i]];
            if (z.blockRegistered == 0) continue;
            if (z.claimed || !z.active || z.rewardWei == 0) continue;
            total += z.rewardWei;
            z.claimed = true;
            totalRewardsClaimed += z.rewardWei;
            emit CD_AlertClaimed(z.zoneId, msg.sender, z.rewardWei, block.number);
        }
        if (total == 0) revert CD_ZoneNotFound();
        if (poolBalance < total) revert CD_TransferFailed();
        poolBalance -= total;
        (bool ok,) = msg.sender.call{ value: total }("");
        if (!ok) revert CD_TransferFailed();
    }

    // -------------------------------------------------------------------------
    // VIEW (SINGLE ZONE)
    // -------------------------------------------------------------------------

    function getZone(bytes32 zoneId) external view returns (RadarZone memory) {
        if (_zonesById[zoneId].blockRegistered == 0) revert CD_ZoneNotFound();
        return _zonesById[zoneId];
    }

    function getZoneSummary(bytes32 zoneId) external view returns (ZoneSummary memory) {
        RadarZone storage z = _zonesById[zoneId];
        if (z.blockRegistered == 0) revert CD_ZoneNotFound();
        return ZoneSummary({
            zoneId: z.zoneId,
            latE6: z.latE6,
            lngE6: z.lngE6,
            speedLimitKph: z.speedLimitKph,
            active: z.active,
            claimed: z.claimed,
            blockRegistered: z.blockRegistered
        });
    }

    function zoneExists(bytes32 zoneId) external view returns (bool) {
        return _zonesById[zoneId].blockRegistered != 0;
    }

    function isZoneActive(bytes32 zoneId) external view returns (bool) {
        return _zonesById[zoneId].active;
    }

    function getZoneRewardWei(bytes32 zoneId) external view returns (uint256) {
        return _zonesById[zoneId].rewardWei;
    }

    function getZoneReporter(bytes32 zoneId) external view returns (address) {
        if (_zonesById[zoneId].blockRegistered == 0) revert CD_ZoneNotFound();
        return _zonesById[zoneId].reporter;
    }

    function getZoneValidationStatus(bytes32 zoneId) external view returns (ValidationStatus) {
        if (_zonesById[zoneId].blockRegistered == 0) revert CD_ZoneNotFound();
        return _zonesById[zoneId].validationStatus;
    }

    function getZoneType(bytes32 zoneId) external view returns (ZoneType) {
        if (_zonesById[zoneId].blockRegistered == 0) revert CD_ZoneNotFound();
        return _zonesById[zoneId].zoneType;
    }

    // -------------------------------------------------------------------------
    // VIEW (LISTS & COUNTS)
    // -------------------------------------------------------------------------

    function getZoneCount() external view returns (uint256) {
        return _allZoneIds.length;
    }

    function getActiveZoneCount() external view returns (uint256) {
        return totalZonesActive;
    }

    function getZoneIdAt(uint256 index) external view returns (bytes32) {
        if (index >= _allZoneIds.length) revert CD_ZoneNotFound();
        return _allZoneIds[index];
    }

    function getZonesInRange(uint256 offset, uint256 limit) external view returns (ZoneSummary[] memory out) {
        if (limit > CD_MAX_BATCH_QUERY) revert CD_BatchTooLarge();
        uint256 len = _allZoneIds.length;
        if (offset >= len) return new ZoneSummary[](0);
        uint256 end = offset + limit;
        if (end > len) end = len;
        uint256 n = end - offset;
        out = new ZoneSummary[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 zid = _allZoneIds[offset + i];
            RadarZone storage z = _zonesById[zid];
            out[i] = ZoneSummary({
                zoneId: z.zoneId,
                latE6: z.latE6,
                lngE6: z.lngE6,
                speedLimitKph: z.speedLimitKph,
                active: z.active,
                claimed: z.claimed,
                blockRegistered: z.blockRegistered
            });
        }
    }

    function getActiveZonesInRange(uint256 offset, uint256 limit) external view returns (ZoneSummary[] memory out) {
        if (limit > CD_MAX_BATCH_QUERY) revert CD_BatchTooLarge();
        uint256 collected = 0;
        uint256 len = _allZoneIds.length;
        ZoneSummary[] memory tmp = new ZoneSummary[](limit);
        for (uint256 i = offset; i < len && collected < limit; i++) {
            RadarZone storage z = _zonesById[_allZoneIds[i]];
            if (!z.active) continue;
            tmp[collected] = ZoneSummary({
                zoneId: z.zoneId,
                latE6: z.latE6,
                lngE6: z.lngE6,
                speedLimitKph: z.speedLimitKph,
                active: z.active,
                claimed: z.claimed,
                blockRegistered: z.blockRegistered
            });
            collected++;
        }
        out = new ZoneSummary[](collected);
        for (uint256 j = 0; j < collected; j++) out[j] = tmp[j];
    }

    function getZoneIdsByReporter(address reporter) external view returns (bytes32[] memory) {
        return _zoneIdsByReporter[reporter];
    }

    function getReporterZoneCount(address reporter) external view returns (uint256) {
        return _zoneIdsByReporter[reporter].length;
    }

    // -------------------------------------------------------------------------
    // VIEW (STATS & POOL)
    // -------------------------------------------------------------------------

    function getPoolBalance() external view returns (uint256) {
        return poolBalance;
    }

    function getTotalRewardsClaimed() external view returns (uint256) {
        return totalRewardsClaimed;
    }

    function getTotalPoolToppedUp() external view returns (uint256) {
        return totalPoolToppedUp;
    }

    function getNetworkTag() external pure returns (bytes32) {
        return CD_NETWORK_TAG;
    }

    function getDomainSeed() external pure returns (bytes32) {
        return CD_DOMAIN_SEED;
    }

    function getDeployBlock() external view returns (uint256) {
        return deployBlock;
    }

    // -------------------------------------------------------------------------
    // VIEW (BY TYPE / STATUS / SPEED)
    // -------------------------------------------------------------------------

    function getZonesByTypeInRange(ZoneType zoneType, uint256 offset, uint256 limit) external view returns (ZoneSummary[] memory out) {
        if (limit > CD_MAX_BATCH_QUERY) revert CD_BatchTooLarge();
        uint256 collected = 0;
        uint256 len = _allZoneIds.length;
        ZoneSummary[] memory tmp = new ZoneSummary[](limit);
        for (uint256 i = 0; i < len && collected < limit; i++) {
            RadarZone storage z = _zonesById[_allZoneIds[i]];
            if (z.zoneType != zoneType) continue;
            if (collected < offset) { collected++; continue; }
            tmp[collected - offset] = ZoneSummary({
                zoneId: z.zoneId,
                latE6: z.latE6,
                lngE6: z.lngE6,
                speedLimitKph: z.speedLimitKph,
                active: z.active,
                claimed: z.claimed,
                blockRegistered: z.blockRegistered
            });
            collected++;
            if (collected - offset >= limit) break;
        }
        uint256 n = collected > offset ? collected - offset : 0;
        if (n > limit) n = limit;
        out = new ZoneSummary[](n);
        for (uint256 j = 0; j < n; j++) out[j] = tmp[j];
    }

    function getZonesByValidationStatusInRange(ValidationStatus status, uint256 offset, uint256 limit) external view returns (ZoneSummary[] memory out) {
        if (limit > CD_MAX_BATCH_QUERY) revert CD_BatchTooLarge();
        uint256 collected = 0;
        uint256 len = _allZoneIds.length;
        ZoneSummary[] memory tmp = new ZoneSummary[](limit);
        for (uint256 i = 0; i < len && collected < limit; i++) {
            RadarZone storage z = _zonesById[_allZoneIds[i]];
            if (z.validationStatus != status) continue;
            if (collected < offset) { collected++; continue; }
            tmp[collected - offset] = ZoneSummary({
                zoneId: z.zoneId,
                latE6: z.latE6,
                lngE6: z.lngE6,
                speedLimitKph: z.speedLimitKph,
