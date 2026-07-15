import { type Locale, translate } from "../i18n"
import { escapeHtml } from "../views/layout"

export type EmailContent = {
  readonly subject: string
  readonly html: string
  readonly text: string
}

export function magicLinkEmail(url: string, locale: Locale = "en"): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: translate(locale, "Your KeyForge sign-in link"),
    text: `${translate(locale, "Sign in to KeyForge:")}\n\n${url}\n\n${translate(locale, "This link expires in 15 minutes. If you did not request it, ignore this email.")}`,
    html: `<p>${escapeHtml(translate(locale, "Sign in to KeyForge by clicking the link below:"))}</p>
<p><a href="${safeUrl}">${escapeHtml(translate(locale, "Sign in to KeyForge"))}</a></p>
<p>${escapeHtml(translate(locale, "This link expires in 15 minutes. If you did not request it, you can safely ignore this email."))}</p>`,
  }
}

export function passwordResetEmail(url: string, locale: Locale = "en"): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: translate(locale, "Reset your KeyForge password"),
    text: `${translate(locale, "Reset your KeyForge password:")}\n\n${url}\n\n${translate(locale, "This link expires in one hour. If you did not request it, ignore this email.")}`,
    html: `<p>${escapeHtml(translate(locale, "Use the secure link below to reset your KeyForge password:"))}</p>
<p><a href="${safeUrl}">${escapeHtml(translate(locale, "Reset password"))}</a></p>
<p>${escapeHtml(translate(locale, "This link expires in one hour. If you did not request it, you can safely ignore this email."))}</p>`,
  }
}

export function accountInvitationEmail(url: string, locale: Locale = "en"): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: translate(locale, "You have been invited to KeyForge"),
    text: `${translate(locale, "An administrator created a KeyForge account for you. Set your password to accept the invitation:")}\n\n${url}\n\n${translate(locale, "This single-use link expires in one hour. If you were not expecting this invitation, ignore this email.")}`,
    html: `<p>${escapeHtml(translate(locale, "An administrator created a KeyForge account for you."))}</p>
<p><a href="${safeUrl}">${escapeHtml(translate(locale, "Set password and accept invitation"))}</a></p>
<p>${escapeHtml(translate(locale, "This single-use link expires in one hour. If you were not expecting this invitation, you can safely ignore this email."))}</p>`,
  }
}

export function emailVerificationEmail(url: string, locale: Locale = "en"): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: translate(locale, "Verify your KeyForge email"),
    text: `${translate(locale, "Verify your KeyForge email address:")}\n\n${url}\n\n${translate(locale, "This link expires in 24 hours.")}`,
    html: `<p>${escapeHtml(translate(locale, "Confirm this email address for your KeyForge account:"))}</p>
<p><a href="${safeUrl}">${escapeHtml(translate(locale, "Verify email"))}</a></p>
<p>${escapeHtml(translate(locale, "This link expires in 24 hours."))}</p>`,
  }
}

export function emailChangeEmail(url: string, locale: Locale = "en"): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: translate(locale, "Confirm your new KeyForge email"),
    text: `${translate(locale, "Confirm this as your new KeyForge email address:")}\n\n${url}\n\n${translate(locale, "This single-use link expires in 24 hours. If you did not request this change, secure your account immediately.")}`,
    html: `<p>${escapeHtml(translate(locale, "Confirm this as the new email address for your KeyForge account:"))}</p>
<p><a href="${safeUrl}">${escapeHtml(translate(locale, "Confirm new email"))}</a></p>
<p>${escapeHtml(translate(locale, "This single-use link expires in 24 hours. If you did not request this change, secure your account immediately."))}</p>`,
  }
}
