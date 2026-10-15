import { describe, expect, it } from "vitest";
import { hasRolePermission } from "../src/lib/permissions";
import { isAdult, profileSchema, reportSchema } from "../src/lib/validation";
import { formatMinorUnits, minorUnitsToInput, parseMoneyToMinorUnits } from "../src/lib/money";
import { dateOfBirthAtAge, getAge } from "../src/lib/search";
import { allowRequest } from "../src/lib/rate-limit";

describe("role permission boundaries", () => {
  it("keeps Developer access technical unless the Owner explicitly grants more", () => {
    expect(hasRolePermission("DEVELOPER", "technical.diagnostics.read")).toBe(true);
    expect(hasRolePermission("DEVELOPER", "business.plans.manage")).toBe(false);
    expect(hasRolePermission("DEVELOPER", "business.plans.manage", ["business.plans.manage"])).toBe(true);
  });

  it("gives Moderators safety permissions but not business controls", () => {
    expect(hasRolePermission("MODERATOR", "trust.reports.manage")).toBe(true);
    expect(hasRolePermission("MODERATOR", "business.payments.read")).toBe(false);
    expect(hasRolePermission("MEMBER", "technical.diagnostics.read")).toBe(false);
    expect(hasRolePermission("MEMBER", "business.dashboard.read", ["business.dashboard.read"])).toBe(false);
    expect(hasRolePermission("OWNER", "business.plans.manage")).toBe(true);
  });
});

describe("age eligibility and search dates", () => {
  const now = new Date("2026-10-15T12:00:00.000Z");

  it("requires an exact adult age threshold", () => {
    expect(isAdult("2008-10-15", now)).toBe(true);
    expect(isAdult("2008-10-16", now)).toBe(false);
    expect(isAdult("not-a-date", now)).toBe(false);
  });

  it("calculates a calendar age and clamps leap-day dates", () => {
    expect(getAge("2008-10-15", now)).toBe(18);
    expect(getAge("2008-10-16", now)).toBe(17);
    expect(dateOfBirthAtAge(1, new Date("2024-02-29T00:00:00.000Z"))).toBe("2023-02-28");
  });

  it("validates profile and report payloads before server writes", () => {
    expect(profileSchema.safeParse({
      displayName: "Sam", birthDate: "2008-10-15", gender: "prefer_not_to_say",
      maritalStatus: "never_married", visibility: "private",
    }).success).toBe(true);
    expect(profileSchema.safeParse({
      displayName: "Sam", birthDate: "2009-10-15", gender: "prefer_not_to_say",
      maritalStatus: "never_married", visibility: "private",
    }).success).toBe(false);
    expect(reportSchema.safeParse({ reportedUserId: "bad", reason: "other" }).success).toBe(false);
  });
});

describe("currency-aware integer minor units", () => {
  it("uses the ISO currency's minor-unit precision without floating point", () => {
    expect(parseMoneyToMinorUnits("1299.50", "INR")).toBe(129950);
    expect(parseMoneyToMinorUnits("1299", "JPY")).toBe(1299);
    expect(parseMoneyToMinorUnits("10.001", "INR")).toBeNull();
    expect(parseMoneyToMinorUnits("1.1", "JPY")).toBeNull();
    expect(parseMoneyToMinorUnits("1", "XXX")).toBeNull();
    expect(minorUnitsToInput(129950, "INR")).toBe("1299.50");
    expect(formatMinorUnits(129950, "INR")).toContain("1,299.50");
  });
});

describe("request throttling", () => {
  it("limits repeated requests within a window and resets after expiry", () => {
    expect(allowRequest("test-user-1", 2, 1000, 100)).toBe(true);
    expect(allowRequest("test-user-1", 2, 1000, 200)).toBe(true);
    expect(allowRequest("test-user-1", 2, 1000, 300)).toBe(false);
    expect(allowRequest("test-user-1", 2, 1000, 1100)).toBe(true);
  });
});
