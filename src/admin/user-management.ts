import { createAccountInvitationToken } from "../auth/account-tokens"
import { passwordMeetsPolicy, setUserPassword } from "../auth/password"
import {
  createUser,
  deleteUser,
  getUserByAlias,
  getUserByEmail,
  listGroups,
  setUserGroups,
} from "../db/queries/users"
import { enqueueEmail } from "../email/sender"
import { accountInvitationEmail } from "../email/templates"
import type { Locale } from "../i18n"
import type { User } from "../types/domain"

export type ManagedUserInput = {
  readonly email: string
  readonly alias: string
  readonly name?: string | null
  readonly emailVerified: boolean
  readonly password?: string
  readonly groupIds: readonly string[]
  readonly locale?: Locale
}

export type ManagedUserResult =
  | {
      readonly ok: true
      readonly user: User
      readonly groups: readonly string[]
      readonly invitationSent: boolean
    }
  | {
      readonly ok: false
      readonly reason: "duplicate_email" | "duplicate_alias" | "invalid_groups" | "invalid_password"
    }

/**
 * Create a login-ready user. If no initial password is supplied, email a
 * single-use invitation instead. Delivery failure rolls the new account back
 * so a retry cannot strand an inaccessible duplicate.
 */
export async function createManagedUser(
  env: Env,
  input: ManagedUserInput,
): Promise<ManagedUserResult> {
  const email = input.email.trim().toLowerCase()
  if ((await getUserByEmail(env, email)) !== null) {
    return { ok: false, reason: "duplicate_email" }
  }
  if ((await getUserByAlias(env, input.alias)) !== null) {
    return { ok: false, reason: "duplicate_alias" }
  }

  const groups = await listGroups(env)
  const requestedIds = [...new Set(input.groupIds)]
  const validIds = new Set(groups.map((group) => group.id))
  if (requestedIds.some((id) => !validIds.has(id))) {
    return { ok: false, reason: "invalid_groups" }
  }
  const administrator = groups.some(
    (group) => group.name === "admins" && requestedIds.includes(group.id),
  )
  if (input.password !== undefined && !passwordMeetsPolicy(input.password, administrator)) {
    return { ok: false, reason: "invalid_password" }
  }

  const user = await createUser(env, {
    email,
    alias: input.alias,
    emailVerified: input.emailVerified,
    ...(input.name === undefined ? {} : { name: input.name }),
  })
  try {
    await setUserGroups(env, user.id, requestedIds)
    if (input.password !== undefined) {
      await setUserPassword(env, user.id, input.password)
    } else {
      const { url } = await createAccountInvitationToken(env, user.id, user.email)
      await enqueueEmail(env, {
        to: user.email,
        ...accountInvitationEmail(url, input.locale),
      })
    }
  } catch (error) {
    await deleteUser(env, user.id)
    throw error
  }

  const selectedNames = groups
    .filter((group) => requestedIds.includes(group.id))
    .map((group) => group.name)
  return {
    ok: true,
    user,
    groups: selectedNames,
    invitationSent: input.password === undefined,
  }
}
