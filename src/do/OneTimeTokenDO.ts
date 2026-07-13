import type { OneTimeTokenPayload } from "../types/tokens"
import { OneTimeConsumeDO } from "./base"

/**
 * Single-use token store for magic links, password-reset links, and email
 * verification links (Phase 6). Addressed by token hash.
 */
export class OneTimeTokenDO extends OneTimeConsumeDO<OneTimeTokenPayload> {}
