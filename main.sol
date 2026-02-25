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
