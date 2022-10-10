/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

// SCE constants
const unsigned int kSceInfoMaxArray = 3;
const DWORD kSceSystemFlag = 300;
const DWORD kSceAreaAllFlag = 0xFFFFL;
const std::string kTargetSCEDLL = "scecli.dll";

// Security Profile data structure used by the SCE RPC Protocol
struct SceRegInfo {
  PWSTR RegName;
  PWSTR RegValueData;
  DWORD RegValueType;
  DWORD RegStatus;
};

struct SceProfileInfo {
  DWORD Unk0;
  DWORD MinPasswdAge;
  DWORD MaxPasswdAge;
  DWORD MinPasswdLen;
  DWORD PasswdComplexity;
  DWORD PasswdHistSize;
  DWORD LockoutBadCount;
  DWORD ResetLockoutCount;
  DWORD LockoutDuration;
  DWORD ReqLogonChangePasswd;
  DWORD ForceLogoffExpire;
  PWSTR AdministratorName;
  PWSTR GuestName;
  DWORD Unk1;
  DWORD ClearTextPasswd;
  DWORD LsaAllowAnonymousSidLookup;
  PVOID Unk2;
  PVOID Unk3;
  PVOID Unk4;
  PVOID Unk5;
  PVOID Unk6;
  PVOID Unk7;
  PVOID Unk8;
  PVOID Unk9;
  DWORD MaxLogSize[kSceInfoMaxArray];
  DWORD RetentionLog[kSceInfoMaxArray];
  DWORD RetentionLogDays[kSceInfoMaxArray];
  DWORD RestrictAccessGuest[kSceInfoMaxArray];
  DWORD AuditSystemEvents;
  DWORD AuditLogonEvents;
  DWORD AuditObjectsAccess;
  DWORD AuditPrivilegeUse;
  DWORD AuditPolicyChange;
  DWORD AuditAccountManage;
  DWORD AuditProcessTracking;
  DWORD AuditDSAccess;
  DWORD AuditAccountLogon;
  DWORD AuditFull;
  DWORD RegInfoCount;
  SceRegInfo* RegInfoData;
  DWORD EnableAdminAccount;
  DWORD EnableGuestAccount;
};

// Helper function to perform run-time dynamic linking on Windows.
// This helper locates an exported function of a given loaded dll, and returns
// a pointer to the location in memory of this exported function.
bool getExportFromDLL(const std::string& targetDLL,
                      const std::string& targetExport,
                      PVOID& exportAddr) {
  // sanity check on input
  if ((targetDLL.empty()) || (targetExport.empty())) {
    return false;
  }

  // Checking if the input DLL is already mapped to memory before loading it.
  // If this is not the case, LoadLibraryExA() gets called to load the module
  // from system32 folder. The returned handle is not going to be closed
  // through FreeLibrary() to keep the module loaded in memory.
  HMODULE hDLL = GetModuleHandleA(targetDLL.c_str());
  if (hDLL == nullptr) {
    hDLL =
        LoadLibraryExA(targetDLL.c_str(), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  }

  // An invalid module handle means that the DLL couldn't be loaded
  if (hDLL == nullptr) {
    return false;
  }

  // Getting the address to an exported function of a given DLL
  PVOID workAddr = GetProcAddress(hDLL, targetExport.c_str());
  if (workAddr == nullptr) {
    return false;
  }

  // Assigning the address for the export in memory so it can be called through
  // a function pointer that matches the target function prototype
  exportAddr = workAddr;

  return true;
}

// Helper function that validates that input is a valid SceProfileInfo data
bool validateSceProfileData(const PVOID& profileData) {
  // Checking that input data is valid
  if (profileData == nullptr) {
    return false;
  }

  // Checking that input data is memory accessible
  if (IsBadReadPtr(&profileData, sizeof(SceProfileInfo))) {
    return false;
  }

  // Casting the input data to the target data structure
  SceProfileInfo* workProfile = reinterpret_cast<SceProfileInfo*>(profileData);

  // Checking if registry info data is accessible
  if (workProfile->RegInfoCount > 0) {
    for (DWORD it = 0; it < workProfile->RegInfoCount; ++it) {
      // Checking that registry array members are accesible
      if (IsBadReadPtr(&(workProfile->RegInfoData[it]), sizeof(SceRegInfo))) {
        return false;
      }
    }
  }

  return true;
}

// This helper frees previously allocated security configuration data
// by calling SceGetSecurityProfileInfo(), which in turn is a wrapper of an
// SCE RPC client call that frees profile data allocated memory.
Status releaseSceProfileData(const PVOID& profileData) {
  // sanity check on input
  if (!validateSceProfileData(profileData)) {
    return Status::failure("Invalid profile data was provided");
  }

  // This is the function prototype of undocumented SceFreeProfileMemory()
  // Safe to use - the function prototype has not changed since its creation
  using SceFreeProfileMemoryPtr = DWORD (*)(PVOID data);

  // This function can be called through a DLL export in scecli.dll
  // Static is used to ensure that runtime linking is performed once.
  static SceFreeProfileMemoryPtr SceFreeProfileMemory = nullptr;

  if (SceFreeProfileMemory == nullptr) {
    PVOID exportAddr = nullptr;

    if (!getExportFromDLL(
            kTargetSCEDLL.c_str(), "SceFreeProfileMemory", exportAddr)) {
      return Status::failure("SceFreeProfileMemory could not be loaded");
    }

    if (exportAddr == nullptr) {
      return Status::failure("SceFreeProfileMemory export is not valid");
    }

    SceFreeProfileMemory =
        reinterpret_cast<SceFreeProfileMemoryPtr>(exportAddr);
  }

  // Calling the runtime-linked function
  DWORD retCode = SceFreeProfileMemory(profileData);
  if (retCode != ERROR_SUCCESS) {
    return Status::failure("SceFreeProfileMemory call failed with error " +
                           std::to_string(retCode));
  }

  return Status::success();
}

// This helper gets the machine security configuration data by calling
// SceGetSecurityProfileInfo(), which in turn is a wrapper of an
// SCE RPC client call that retrieves this data from the SCE RPC server.
Status getSceSecurityProfileInfo(PVOID& profileData, DWORD securityArea) {
  // This is the function prototype of undocumented SceGetSecurityProfileInfo()
  // Safe to use - the function prototype has not changed since its creation
  using GetSecProfileInfoFnPtr = DWORD (*)(PVOID profileHandle,
                                           DWORD type,
                                           DWORD securityArea,
                                           PVOID profileInfo,
                                           PVOID errorInfo);

  // This function can be called through a DLL export in scecli.dll
  // Static is used to ensure that runtime linking is performed once.
  static GetSecProfileInfoFnPtr GetSecurityProfileInfo = nullptr;

  if (GetSecurityProfileInfo == nullptr) {
    PVOID exportAddr = nullptr;
    if (!getExportFromDLL(
            kTargetSCEDLL.c_str(), "SceGetSecurityProfileInfo", exportAddr)) {
      return Status::failure("SceGetSecurityProfileInfo could not be loaded");
    }

    if (exportAddr == nullptr) {
      return Status::failure("SceGetSecurityProfileInfo export is not valid");
    }

    GetSecurityProfileInfo =
        reinterpret_cast<GetSecProfileInfoFnPtr>(exportAddr);
  }

  // Calling the runtime-linked function and returning the obtained data
  PVOID workProfileData = nullptr;
  DWORD retCode = GetSecurityProfileInfo(
      nullptr, kSceSystemFlag, securityArea, &workProfileData, nullptr);

  if (retCode != ERROR_SUCCESS) {
    return Status::failure("GetSecurityProfileInfo call failed with error " +
                           std::to_string(retCode));
  }

  if (!validateSceProfileData(workProfileData)) {
    return Status::failure("GetSecurityProfileInfo returned invalid data");
  }

  profileData = workProfileData;

  return Status::success();
}

QueryData genSystemSecurityRegistry(QueryContext& context) {
  QueryData results;

  // Getting the profile data blob first
  PVOID profileDataBlob = nullptr;
  Status secProfileStatus =
      getSceSecurityProfileInfo(profileDataBlob, kSceAreaAllFlag);
  if (!secProfileStatus.ok()) {
    LOG(ERROR) << "Failed to retrieve security profile data "
               << secProfileStatus.getMessage();

    return results;
  }

  // Then casting the blob to a SceProfileInfo data structure
  SceProfileInfo* profileData =
      reinterpret_cast<SceProfileInfo*>(profileDataBlob);

  for (DWORD it = 0; it < profileData->RegInfoCount; ++it) {
    Row seceditRow;
    SceRegInfo* workReg =
        reinterpret_cast<SceRegInfo*>(&profileData->RegInfoData[it]);

    if (workReg == nullptr) {
      continue;
    }
    PWSTR regName = profileData->RegInfoData[it].RegName;
    PWSTR regValueData = profileData->RegInfoData[it].RegValueData;
    DWORD regValueType = profileData->RegInfoData[it].RegValueType;

    if ((regName == nullptr) || (regValueData == nullptr)) {
      continue;
    }

    seceditRow["RegistryName"] = wstringToString(regName);
    seceditRow["RegistryType"] = INTEGER(static_cast<int>(regValueType));
    seceditRow["RegistryValue"] = wstringToString(regValueData);

    results.push_back(std::move(seceditRow));
  }

  // And finally releasing the allocated data
  Status secReleaseProfileData = releaseSceProfileData(profileDataBlob);
  if (!secReleaseProfileData.ok()) {
    LOG(ERROR) << "Failed to release security profile data "
               << secReleaseProfileData.getMessage();
  }

  return results;
}

QueryData genSystemSecurityPolicies(QueryContext& context) {
  QueryData results;

  // Getting the profile data blob first
  PVOID profileDataBlob = nullptr;
  Status secProfileStatus =
      getSceSecurityProfileInfo(profileDataBlob, kSceAreaAllFlag);
  if (!secProfileStatus.ok()) {
    LOG(ERROR) << "Failed to retrieve security profile data "
               << secProfileStatus.getMessage();

    return results;
  }

  // Then casting the blob to a SceProfileInfo data structure
  SceProfileInfo* profileData =
      reinterpret_cast<SceProfileInfo*>(profileDataBlob);

  // Adding output data
  Row seceditRow;
  seceditRow["MinimumPasswordAge"] =
      INTEGER(static_cast<int>(profileData->MinPasswdAge));
  seceditRow["MaximumPasswordAge"] =
      INTEGER(static_cast<int>(profileData->MaxPasswdAge));
  seceditRow["MinimumPasswordLength"] =
      INTEGER(static_cast<int>(profileData->MinPasswdLen));
  seceditRow["PasswordComplexity"] =
      INTEGER(static_cast<int>(profileData->PasswdComplexity));
  seceditRow["PasswordHistorySize"] =
      INTEGER(static_cast<int>(profileData->PasswdHistSize));
  seceditRow["LockoutBadCount"] =
      INTEGER(static_cast<int>(profileData->LockoutBadCount));
  seceditRow["RequireLogonToChangePassword"] =
      INTEGER(static_cast<int>(profileData->ReqLogonChangePasswd));
  seceditRow["ForceLogoffWhenHourExpire"] =
      INTEGER(static_cast<int>(profileData->ForceLogoffExpire));
  seceditRow["NewAdministratorName"] =
      wstringToString(profileData->AdministratorName);
  seceditRow["NewGuestName"] = wstringToString(profileData->GuestName);
  seceditRow["ClearTextPassword"] =
      INTEGER(static_cast<int>(profileData->ClearTextPasswd));
  seceditRow["LSAAnonymousNameLookup"] =
      INTEGER(static_cast<int>(profileData->LsaAllowAnonymousSidLookup));
  seceditRow["EnableAdminAccount"] =
      INTEGER(static_cast<int>(profileData->EnableAdminAccount));
  seceditRow["EnableGuestAccount"] =
      INTEGER(static_cast<int>(profileData->EnableGuestAccount));
  seceditRow["AuditSystemEvents"] =
      INTEGER(static_cast<int>(profileData->AuditSystemEvents));
  seceditRow["AuditLogonEvents"] =
      INTEGER(static_cast<int>(profileData->AuditLogonEvents));
  seceditRow["AuditObjectAccess"] =
      INTEGER(static_cast<int>(profileData->AuditObjectsAccess));
  seceditRow["AuditPrivilegeUse"] =
      INTEGER(static_cast<int>(profileData->AuditPrivilegeUse));
  seceditRow["AuditPolicyChange"] =
      INTEGER(static_cast<int>(profileData->AuditPolicyChange));
  seceditRow["AuditAccountManage"] =
      INTEGER(static_cast<int>(profileData->AuditAccountManage));
  seceditRow["AuditProcessTracking"] =
      INTEGER(static_cast<int>(profileData->AuditProcessTracking));
  seceditRow["AuditDSAccess"] =
      INTEGER(static_cast<int>(profileData->AuditDSAccess));
  seceditRow["AuditAccountLogon"] =
      INTEGER(static_cast<int>(profileData->AuditAccountLogon));

  results.push_back(std::move(seceditRow));

  // And finally releasing the allocated data
  Status secReleaseProfileData = releaseSceProfileData(profileDataBlob);
  if (!secReleaseProfileData.ok()) {
    LOG(ERROR) << "Failed to release security profile data "
               << secReleaseProfileData.getMessage();
  }

  return results;
}

} // namespace tables
} // namespace osquery
