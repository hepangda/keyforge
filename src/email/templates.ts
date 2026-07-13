import { escapeHtml } from "../views/layout"

export type EmailContent = {
  readonly subject: string
  readonly html: string
  readonly text: string
}

export function magicLinkEmail(url: string): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: "Your KeyForge sign-in link",
    text: `Sign in to KeyForge:\n\n${url}\n\nThis link expires in 15 minutes. If you did not request it, ignore this email.`,
    html: `<p>Sign in to KeyForge by clicking the link below:</p>
<p><a href="${safeUrl}">Sign in to KeyForge</a></p>
<p>This link expires in 15 minutes. If you did not request it, you can safely ignore this email.</p>`,
  }
}

export function passwordResetEmail(url: string): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: "Reset your KeyForge password",
    text: `Reset your KeyForge password:\n\n${url}\n\nThis link expires in one hour. If you did not request it, ignore this email.`,
    html: `<p>Use the secure link below to reset your KeyForge password:</p>
<p><a href="${safeUrl}">Reset password</a></p>
<p>This link expires in one hour. If you did not request it, you can safely ignore this email.</p>`,
  }
}

export function accountInvitationEmail(url: string): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: "You have been invited to KeyForge",
    text: `An administrator created a KeyForge account for you. Set your password to accept the invitation:\n\n${url}\n\nThis single-use link expires in one hour. If you were not expecting this invitation, ignore this email.`,
    html: `<p>An administrator created a KeyForge account for you.</p>
<p><a href="${safeUrl}">Set password and accept invitation</a></p>
<p>This single-use link expires in one hour. If you were not expecting this invitation, you can safely ignore this email.</p>`,
  }
}

export function emailVerificationEmail(url: string): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: "Verify your KeyForge email",
    text: `Verify your KeyForge email address:\n\n${url}\n\nThis link expires in 24 hours.`,
    html: `<p>Confirm this email address for your KeyForge account:</p>
<p><a href="${safeUrl}">Verify email</a></p>
<p>This link expires in 24 hours.</p>`,
  }
}

export function emailChangeEmail(url: string): EmailContent {
  const safeUrl = escapeHtml(url)
  return {
    subject: "Confirm your new KeyForge email",
    text: `Confirm this as your new KeyForge email address:\n\n${url}\n\nThis single-use link expires in 24 hours. If you did not request this change, secure your account immediately.`,
    html: `<p>Confirm this as the new email address for your KeyForge account:</p>
<p><a href="${safeUrl}">Confirm new email</a></p>
<p>This single-use link expires in 24 hours. If you did not request this change, secure your account immediately.</p>`,
  }
}
