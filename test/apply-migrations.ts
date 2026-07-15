import { applyD1Migrations, env } from "cloudflare:test"
import { setUserPassword } from "../src/auth/password"
import { createUser, getGroupByName, setUserGroups } from "../src/db/queries/users"

// Apply D1 migrations to the isolated per-file seed storage before any test runs.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS)

// Test-only fixture. Production migrations intentionally contain no credentials.
const admin = await createUser(env, {
  email: "admin",
  name: "Administrator",
  emailVerified: true,
})
await setUserPassword(env, admin.id, "test-admin-password-2026")
const admins = await getGroupByName(env, "admins")
const employees = await getGroupByName(env, "employees")
if (admins !== null) {
  await setUserGroups(env, admin.id, employees === null ? [admins.id] : [admins.id, employees.id])
}
