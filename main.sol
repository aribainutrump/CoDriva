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
