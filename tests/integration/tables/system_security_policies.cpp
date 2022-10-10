/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for system_security_policies
// Spec file: specs/windows/system_security_policies.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class WindowsSecurityTests : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(WindowsSecurityTests, test_sanity_policies) {
  auto const data = execute_query("select * from system_security_policies");

  ValidationMap rowMap = {
      {"MinimumPasswordAge", IntType | NonEmpty | NonNull},
      {"MaximumPasswordAge", IntType | NonEmpty | NonNull},
      {"MinimumPasswordLength", IntType | NonEmpty | NonNull},
      {"PasswordComplexity", IntType | NonEmpty | NonNull},
      {"PasswordHistorySize", IntType | NonEmpty | NonNull},
      {"LockoutBadCount", IntType | NonEmpty | NonNull},
      {"RequireLogonToChangePassword", IntType | NonEmpty | NonNull},
      {"ForceLogoffWhenHourExpire", IntType | NonEmpty | NonNull},
      {"NewAdministratorName", NonEmptyString},
      {"NewGuestName", NonEmptyString},
      {"ClearTextPassword", IntType | NonEmpty | NonNull},
      {"LSAAnonymousNameLookup", IntType | NonEmpty | NonNull},
      {"EnableAdminAccount", IntType | NonEmpty | NonNull},
      {"EnableGuestAccount", IntType | NonEmpty | NonNull},
      {"AuditSystemEvents", IntType | NonEmpty | NonNull},
      {"AuditLogonEvents", IntType | NonEmpty | NonNull},
      {"AuditObjectAccess", IntType | NonEmpty | NonNull},
      {"AuditPrivilegeUse", IntType | NonEmpty | NonNull},
      {"AuditPolicyChange", IntType | NonEmpty | NonNull},
      {"AuditAccountManage", IntType | NonEmpty | NonNull},
      {"AuditProcessTracking", IntType | NonEmpty | NonNull},
      {"AuditDSAccess", IntType | NonEmpty | NonNull},
      {"AuditAccountLogon", IntType | NonEmpty | NonNull},
  };
  validate_rows(data, rowMap);
}

TEST_F(WindowsSecurityTests, test_sanity_registry) {
  auto const data = execute_query("select * from system_security_registry");

  ValidationMap rowMap = {
      {"RegistryName", NonEmptyString},
      {"RegistryType", NonEmptyString},
      {"RegistryValue", NonNull},
  };
  validate_rows(data, rowMap);
}

} // namespace table_tests
} // namespace osquery
