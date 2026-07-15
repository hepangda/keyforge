/**
 * Core domain types. Branded primitives make illegal mixing (a UserId where a
 * ClientId is expected) a compile error. Brands are applied at the D1 query
 * boundary — inside the app, code receives already-typed values.
 */

declare const __brand: unique symbol
export type Brand<T, B extends string> = T & { readonly [__brand]: B }

export type UserId = Brand<string, "UserId">
export type ClientId = Brand<string, "ClientId">
export type SessionId = Brand<string, "SessionId">
export type ResourceUri = Brand<string, "ResourceUri">
export type GroupId = Brand<string, "GroupId">

// The one sanctioned place for a brand `as`: the D1 parse boundary.
export const asUserId = (value: string): UserId => value as UserId
export const asClientId = (value: string): ClientId => value as ClientId
export const asSessionId = (value: string): SessionId => value as SessionId
export const asResourceUri = (value: string): ResourceUri => value as ResourceUri
export const asGroupId = (value: string): GroupId => value as GroupId

/** OAuth client confidentiality. */
export const CLIENT_TYPES = ["public", "confidential"] as const
export type ClientType = (typeof CLIENT_TYPES)[number]

/** What kind of thing a client is — drives grant/scope policy. */
export const CLIENT_KINDS = ["application", "device", "service"] as const
export type ClientKind = (typeof CLIENT_KINDS)[number]

/** Lifecycle of a device authorization session. */
export const DEVICE_STATUSES = ["pending", "approved", "denied", "expired", "consumed"] as const
export type DeviceStatus = (typeof DEVICE_STATUSES)[number]

export const AUTH_METHODS = ["password", "magic_link", "passkey"] as const
export type AuthMethod = (typeof AUTH_METHODS)[number]

export type SessionRecord = {
  readonly id: SessionId
  readonly userId: UserId
  readonly authMethod: AuthMethod
  readonly authTime: number
  readonly passkeyAuthenticated: boolean
  readonly createdAt: number
  readonly lastSeenAt: number
  readonly expiresAt: number
}

/** A parsed user record as it flows through the application interior. */
export type User = {
  readonly id: UserId
  readonly email: string
  readonly alias: string
  readonly emailVerified: boolean
  readonly name: string | null
  readonly picture: string | null
  readonly disabled: boolean
  readonly createdAt: number
}

/** A resolved OAuth client. */
export type OAuthClient = {
  readonly clientId: ClientId
  readonly name: string
  readonly type: ClientType
  readonly clientKind: ClientKind
  readonly clientSecretHash: string | null
  readonly redirectUris: readonly string[]
  readonly postLogoutRedirectUris: readonly string[]
  readonly allowedScopes: readonly string[]
  readonly allowedGrantTypes: readonly string[]
  readonly allowedResources: readonly string[]
  readonly defaultResource: string | null
  readonly requirePkce: boolean
  readonly enabled: boolean
}

/** A registered protected resource (audience). */
export type OAuthResource = {
  readonly resourceUri: ResourceUri
  readonly name: string
  readonly allowedScopes: readonly string[]
  readonly enabled: boolean
}
