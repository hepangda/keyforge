import type { NonEnglishLocale } from "./index"

type LocalizedMessage = Readonly<Record<NonEnglishLocale, string>>

/**
 * English source messages and their supported translations.
 *
 * Keeping the English sentence as the lookup key makes existing server-side
 * validation messages localizable without coupling domain code to UI message
 * identifiers. Every entry must provide every non-English locale.
 */
export const MESSAGE_CATALOG = {
  Language: { "zh-CN": "语言", ja: "言語" },
  "Follow browser": { "zh-CN": "跟随浏览器", ja: "ブラウザーに合わせる" },
  Apply: { "zh-CN": "应用", ja: "適用" },
  Sections: { "zh-CN": "页面分区", ja: "セクション" },
  "Confirm your identity": { "zh-CN": "确认您的身份", ja: "本人確認" },
  "Your name and profile details": { "zh-CN": "您的姓名和个人资料", ja: "名前とプロフィール情報" },
  "Your email address": { "zh-CN": "您的电子邮箱地址", ja: "メールアドレス" },
  "Stay signed in while you're away": {
    "zh-CN": "在您离开时保持登录",
    ja: "離席中もログイン状態を維持",
  },
  "Your postal address": { "zh-CN": "您的邮寄地址", ja: "住所" },
  "Your phone number": { "zh-CN": "您的电话号码", ja: "電話番号" },
  "Your group memberships": { "zh-CN": "您的群组成员身份", ja: "所属グループ" },
  "This app isn't requesting any specific permissions.": {
    "zh-CN": "此应用未请求任何特定权限。",
    ja: "このアプリは特定の権限を要求していません。",
  },
  "Sign in again": { "zh-CN": "重新登录", ja: "再度ログイン" },
  "Sign in to KeyForge": { "zh-CN": "登录 KeyForge", ja: "KeyForge にログイン" },
  "The application requested fresh authentication before continuing.": {
    "zh-CN": "应用要求您重新验证身份后再继续。",
    ja: "続行するには、アプリケーションの要求により再認証が必要です。",
  },
  "Enter your credentials to continue to your account.": {
    "zh-CN": "输入您的凭据以继续访问账户。",
    ja: "認証情報を入力してアカウントに進んでください。",
  },
  "Email or username": { "zh-CN": "电子邮箱或用户名", ja: "メールアドレスまたはユーザー名" },
  Password: { "zh-CN": "密码", ja: "パスワード" },
  "Forgot password?": { "zh-CN": "忘记密码？", ja: "パスワードを忘れた場合" },
  "Sign in": { "zh-CN": "登录", ja: "ログイン" },
  or: { "zh-CN": "或", ja: "または" },
  "Use a passkey": { "zh-CN": "使用通行密钥", ja: "パスキーを使用" },
  "Email me a sign-in link instead": {
    "zh-CN": "改为向我发送登录链接",
    ja: "代わりにログインリンクをメールで受け取る",
  },
  "Waiting for your passkey…": { "zh-CN": "正在等待您的通行密钥…", ja: "パスキーを待っています…" },
  "Passkey sign-in was cancelled.": {
    "zh-CN": "通行密钥登录已取消。",
    ja: "パスキーでのログインはキャンセルされました。",
  },
  "Passkey sign-in could not be completed.": {
    "zh-CN": "无法完成通行密钥登录。",
    ja: "パスキーでのログインを完了できませんでした。",
  },
  "Sign in — KeyForge": { "zh-CN": "登录 — KeyForge", ja: "ログイン — KeyForge" },
  "Sign out?": { "zh-CN": "要退出登录吗？", ja: "ログアウトしますか？" },
  "This browser session will end. Other signed-in devices remain active.": {
    "zh-CN": "此浏览器会话将结束，其他已登录设备不受影响。",
    ja: "このブラウザーのセッションを終了します。他のログイン済みデバイスはそのままです。",
  },
  "Sign out": { "zh-CN": "退出登录", ja: "ログアウト" },
  "Cancel and return to your account": {
    "zh-CN": "取消并返回账户",
    ja: "キャンセルしてアカウントに戻る",
  },
  "Sign out — KeyForge": { "zh-CN": "退出登录 — KeyForge", ja: "ログアウト — KeyForge" },
  "the requesting application": { "zh-CN": "发起请求的应用", ja: "要求元のアプリケーション" },
  "{application} requested that this browser session end. Other signed-in devices remain active.": {
    "zh-CN": "{application} 请求结束此浏览器会话，其他已登录设备不受影响。",
    ja: "{application} から、このブラウザーのセッションを終了するよう要求されました。他のログイン済みデバイスはそのままです。",
  },
  "Sign out and continue": { "zh-CN": "退出并继续", ja: "ログアウトして続行" },
  "Authorize {client}": { "zh-CN": "授权 {client}", ja: "{client} を承認" },
  "wants to access your KeyForge account.": {
    "zh-CN": "想要访问您的 KeyForge 账户。",
    ja: "があなたの KeyForge アカウントへのアクセスを求めています。",
  },
  Resource: { "zh-CN": "资源", ja: "リソース" },
  Deny: { "zh-CN": "拒绝", ja: "拒否" },
  "Allow access": { "zh-CN": "允许访问", ja: "アクセスを許可" },
  "Authorize — KeyForge": { "zh-CN": "授权 — KeyForge", ja: "承認 — KeyForge" },
  "Request error": { "zh-CN": "请求错误", ja: "リクエストエラー" },
  "Return to sign in": { "zh-CN": "返回登录", ja: "ログインに戻る" },
  "Error — KeyForge": { "zh-CN": "错误 — KeyForge", ja: "エラー — KeyForge" },
  "Connect a device": { "zh-CN": "连接设备", ja: "デバイスを接続" },
  "Enter the code shown on your device to continue.": {
    "zh-CN": "输入设备上显示的代码以继续。",
    ja: "デバイスに表示されているコードを入力してください。",
  },
  "Device code": { "zh-CN": "设备代码", ja: "デバイスコード" },
  Continue: { "zh-CN": "继续", ja: "続行" },
  "Connect a device — KeyForge": {
    "zh-CN": "连接设备 — KeyForge",
    ja: "デバイスを接続 — KeyForge",
  },
  "Confirm you want to grant access to this device.": {
    "zh-CN": "确认您希望向此设备授予访问权限。",
    ja: "このデバイスへのアクセスを許可することを確認してください。",
  },
  "Authorize device — KeyForge": {
    "zh-CN": "授权设备 — KeyForge",
    ja: "デバイスを承認 — KeyForge",
  },
  "Device connected": { "zh-CN": "设备已连接", ja: "デバイスを接続しました" },
  "Request denied": { "zh-CN": "请求已拒绝", ja: "リクエストを拒否しました" },
  "You can return to your device — it's now signed in.": {
    "zh-CN": "您可以返回设备，它现在已登录。",
    ja: "デバイスに戻ってください。ログインが完了しました。",
  },
  "The device request was denied. It's safe to close this page.": {
    "zh-CN": "设备请求已被拒绝，您可以安全地关闭此页面。",
    ja: "デバイスのリクエストは拒否されました。このページを閉じても安全です。",
  },
  "Device — KeyForge": { "zh-CN": "设备 — KeyForge", ja: "デバイス — KeyForge" },
  "That code is invalid or has expired.": {
    "zh-CN": "该代码无效或已过期。",
    ja: "コードが無効か、有効期限が切れています。",
  },
  "That authorization request is no longer available.": {
    "zh-CN": "该授权请求已不可用。",
    ja: "その承認リクエストは利用できなくなりました。",
  },
  "This account cannot grant the requested access.": {
    "zh-CN": "此账户无法授予所请求的访问权限。",
    ja: "このアカウントでは、要求されたアクセスを許可できません。",
  },
  "Your session expired. Please try again.": {
    "zh-CN": "您的会话已过期，请重试。",
    ja: "セッションの有効期限が切れました。もう一度お試しください。",
  },
  "That request has no valid resource.": {
    "zh-CN": "该请求没有有效资源。",
    ja: "そのリクエストには有効なリソースがありません。",
  },
  "That request was already handled.": {
    "zh-CN": "该请求已经处理。",
    ja: "そのリクエストはすでに処理されています。",
  },
  "Sign in with email": { "zh-CN": "使用电子邮箱登录", ja: "メールでログイン" },
  "We'll email you a secure link to sign in — no password needed.": {
    "zh-CN": "我们会向您发送安全登录链接，无需密码。",
    ja: "パスワード不要の安全なログインリンクをメールで送信します。",
  },
  Email: { "zh-CN": "电子邮箱", ja: "メールアドレス" },
  "Email me a link": { "zh-CN": "向我发送链接", ja: "リンクをメールで送信" },
  "Back to password sign-in": { "zh-CN": "返回密码登录", ja: "パスワードでのログインに戻る" },
  "Sign in with email — KeyForge": {
    "zh-CN": "使用电子邮箱登录 — KeyForge",
    ja: "メールでログイン — KeyForge",
  },
  "Check your email": { "zh-CN": "请查收电子邮件", ja: "メールを確認してください" },
  "If an account exists for {email}, a sign-in link is on its way.": {
    "zh-CN": "如果 {email} 对应的账户存在，登录链接正在发送。",
    ja: "{email} のアカウントが存在する場合、ログインリンクを送信しました。",
  },
  "The link expires in 15 minutes. You can close this tab after opening it.": {
    "zh-CN": "链接将在 15 分钟后过期。打开链接后即可关闭此标签页。",
    ja: "リンクの有効期限は15分です。リンクを開いた後、このタブを閉じてもかまいません。",
  },
  "Check your email — KeyForge": {
    "zh-CN": "请查收电子邮件 — KeyForge",
    ja: "メールを確認 — KeyForge",
  },
  "Confirm sign in": { "zh-CN": "确认登录", ja: "ログインの確認" },
  "Continue as {email}.": { "zh-CN": "以 {email} 的身份继续。", ja: "{email} として続行します。" },
  Cancel: { "zh-CN": "取消", ja: "キャンセル" },
  "Confirm sign in — KeyForge": {
    "zh-CN": "确认登录 — KeyForge",
    ja: "ログインの確認 — KeyForge",
  },
  "Please try again.": { "zh-CN": "请重试。", ja: "もう一度お試しください。" },
  "This sign-in link is invalid or has expired.": {
    "zh-CN": "此登录链接无效或已过期。",
    ja: "このログインリンクは無効か、有効期限が切れています。",
  },
  "Too many attempts. Please wait and try again.": {
    "zh-CN": "尝试次数过多，请稍后重试。",
    ja: "試行回数が多すぎます。しばらく待ってからもう一度お試しください。",
  },
  "This sign-in request could not be verified.": {
    "zh-CN": "无法验证此登录请求。",
    ja: "このログインリクエストを確認できませんでした。",
  },
  "This account is unavailable.": {
    "zh-CN": "此账户不可用。",
    ja: "このアカウントは利用できません。",
  },
  "Reset your password": { "zh-CN": "重置密码", ja: "パスワードをリセット" },
  "Enter your account email and we'll send a one-time reset link.": {
    "zh-CN": "输入账户电子邮箱，我们会发送一次性重置链接。",
    ja: "アカウントのメールアドレスを入力すると、1回限りのリセットリンクを送信します。",
  },
  "Send reset link": { "zh-CN": "发送重置链接", ja: "リセットリンクを送信" },
  "Back to sign in": { "zh-CN": "返回登录", ja: "ログインに戻る" },
  "Reset password — KeyForge": {
    "zh-CN": "重置密码 — KeyForge",
    ja: "パスワードをリセット — KeyForge",
  },
  "If an account exists for {email}, a reset link is on its way.": {
    "zh-CN": "如果 {email} 对应的账户存在，重置链接正在发送。",
    ja: "{email} のアカウントが存在する場合、リセットリンクを送信しました。",
  },
  "The link expires in one hour and works only once.": {
    "zh-CN": "链接将在一小时后过期，且只能使用一次。",
    ja: "リンクの有効期限は1時間で、1回だけ使用できます。",
  },
  "Accept your invitation": { "zh-CN": "接受邀请", ja: "招待を承諾" },
  "Choose a new password": { "zh-CN": "选择新密码", ja: "新しいパスワードを設定" },
  "Create a password to activate your invited account.": {
    "zh-CN": "创建密码以激活受邀账户。",
    ja: "パスワードを作成して、招待されたアカウントを有効にしてください。",
  },
  "Use at least {minimum} characters and avoid a password used elsewhere.": {
    "zh-CN": "请至少使用 {minimum} 个字符，并避免使用在其他地方用过的密码。",
    ja: "{minimum}文字以上で、他のサービスでは使用していないパスワードを設定してください。",
  },
  "New password": { "zh-CN": "新密码", ja: "新しいパスワード" },
  "Confirm new password": { "zh-CN": "确认新密码", ja: "新しいパスワードを確認" },
  "Accept invitation": { "zh-CN": "接受邀请", ja: "招待を承諾" },
  "Reset password": { "zh-CN": "重置密码", ja: "パスワードをリセット" },
  "Accept invitation — KeyForge": {
    "zh-CN": "接受邀请 — KeyForge",
    ja: "招待を承諾 — KeyForge",
  },
  "Choose a new password — KeyForge": {
    "zh-CN": "选择新密码 — KeyForge",
    ja: "新しいパスワードを設定 — KeyForge",
  },
  "Continue to sign in": { "zh-CN": "继续登录", ja: "ログインに進む" },
  "Recovery temporarily unavailable": {
    "zh-CN": "账户恢复暂时不可用",
    ja: "アカウント復旧は一時的に利用できません",
  },
  "Reset link unavailable": { "zh-CN": "重置链接不可用", ja: "リセットリンクを利用できません" },
  "This password reset link is invalid, expired, or already used.": {
    "zh-CN": "此密码重置链接无效、已过期或已被使用。",
    ja: "このパスワードリセットリンクは無効、有効期限切れ、または使用済みです。",
  },
  "Account unavailable": { "zh-CN": "账户不可用", ja: "アカウントを利用できません" },
  "Passwords must match and contain {minimum} to {maximum} characters.": {
    "zh-CN": "两次密码必须一致，且长度应为 {minimum} 到 {maximum} 个字符。",
    ja: "パスワードは一致し、{minimum}〜{maximum}文字である必要があります。",
  },
  "Invitation accepted": { "zh-CN": "邀请已接受", ja: "招待を承諾しました" },
  "Password reset": { "zh-CN": "密码已重置", ja: "パスワードをリセットしました" },
  "Your account is active and ready to use.": {
    "zh-CN": "您的账户已激活，可以使用。",
    ja: "アカウントが有効になり、利用できるようになりました。",
  },
  "Your new password is ready to use.": {
    "zh-CN": "您的新密码现在可以使用。",
    ja: "新しいパスワードを使用できます。",
  },
  "Verification link unavailable": {
    "zh-CN": "验证链接不可用",
    ja: "確認リンクを利用できません",
  },
  "This email verification link is invalid, expired, or already used.": {
    "zh-CN": "此电子邮箱验证链接无效、已过期或已被使用。",
    ja: "このメール確認リンクは無効、有効期限切れ、または使用済みです。",
  },
  "Verify your email": { "zh-CN": "验证电子邮箱", ja: "メールアドレスを確認" },
  "Confirm {email} as your account email address.": {
    "zh-CN": "确认将 {email} 作为您的账户电子邮箱地址。",
    ja: "{email} をアカウントのメールアドレスとして確認します。",
  },
  "Verify email": { "zh-CN": "验证电子邮箱", ja: "メールを確認" },
  "Verification unavailable": { "zh-CN": "验证不可用", ja: "確認できません" },
  "Email verified": { "zh-CN": "电子邮箱已验证", ja: "メール確認済み" },
  "Your email address is now verified.": {
    "zh-CN": "您的电子邮箱地址现已验证。",
    ja: "メールアドレスの確認が完了しました。",
  },
  "Email change unavailable": { "zh-CN": "无法更改电子邮箱", ja: "メールアドレスを変更できません" },
  "This email change link is invalid, expired, or already used.": {
    "zh-CN": "此电子邮箱更改链接无效、已过期或已被使用。",
    ja: "このメール変更リンクは無効、有効期限切れ、または使用済みです。",
  },
  "Confirm email change": { "zh-CN": "确认更改电子邮箱", ja: "メールアドレス変更の確認" },
  "Change your account email to {email}. This signs out every session.": {
    "zh-CN": "将账户电子邮箱更改为 {email}。这会退出所有会话。",
    ja: "アカウントのメールアドレスを {email} に変更します。すべてのセッションからログアウトします。",
  },
  "Change email": { "zh-CN": "更改电子邮箱", ja: "メールアドレスを変更" },
  "That email address is already in use.": {
    "zh-CN": "该电子邮箱地址已被使用。",
    ja: "そのメールアドレスはすでに使用されています。",
  },
  "Email address changed": { "zh-CN": "电子邮箱地址已更改", ja: "メールアドレスを変更しました" },
  "Your new email is confirmed. Sign in again to continue.": {
    "zh-CN": "您的新电子邮箱已确认。请重新登录以继续。",
    ja: "新しいメールアドレスを確認しました。続行するには再度ログインしてください。",
  },
  "The requested page was not found.": {
    "zh-CN": "未找到请求的页面。",
    ja: "要求されたページが見つかりませんでした。",
  },
  "Something went wrong. Please try again.": {
    "zh-CN": "出现问题，请重试。",
    ja: "問題が発生しました。もう一度お試しください。",
  },
  "Invalid email, username, or password.": {
    "zh-CN": "电子邮箱、用户名或密码无效。",
    ja: "メールアドレス、ユーザー名、またはパスワードが正しくありません。",
  },
  "Your account has been deleted.": {
    "zh-CN": "您的账户已删除。",
    ja: "アカウントは削除されました。",
  },
  "The logout request contains invalid parameters.": {
    "zh-CN": "退出登录请求包含无效参数。",
    ja: "ログアウトリクエストに無効なパラメーターが含まれています。",
  },
  "Invalid post_logout_redirect_uri.": {
    "zh-CN": "post_logout_redirect_uri 无效。",
    ja: "post_logout_redirect_uri が無効です。",
  },
  "id_token_hint does not belong to this session.": {
    "zh-CN": "id_token_hint 不属于此会话。",
    ja: "id_token_hint はこのセッションのものではありません。",
  },
  "Invalid id_token_hint.": { "zh-CN": "id_token_hint 无效。", ja: "id_token_hint が無効です。" },
  "client_id does not match id_token_hint.": {
    "zh-CN": "client_id 与 id_token_hint 不匹配。",
    ja: "client_id が id_token_hint と一致しません。",
  },
  "id_token_hint has an ambiguous audience.": {
    "zh-CN": "id_token_hint 的受众不明确。",
    ja: "id_token_hint の対象（audience）が曖昧です。",
  },
  "client_id or a valid id_token_hint is required for redirect.": {
    "zh-CN": "重定向需要 client_id 或有效的 id_token_hint。",
    ja: "リダイレクトには client_id または有効な id_token_hint が必要です。",
  },
  "Unknown logout client.": {
    "zh-CN": "未知的退出登录客户端。",
    ja: "不明なログアウトクライアントです。",
  },
  "The authorization request contains invalid or oversized parameters.": {
    "zh-CN": "授权请求包含无效或过大的参数。",
    ja: "承認リクエストに無効または大きすぎるパラメーターが含まれています。",
  },
  "client_id must appear exactly once.": {
    "zh-CN": "client_id 必须且只能出现一次。",
    ja: "client_idは1回だけ指定する必要があります。",
  },
  "Missing client_id.": { "zh-CN": "缺少 client_id。", ja: "client_idがありません。" },
  "Unknown client.": { "zh-CN": "未知客户端。", ja: "不明なクライアントです。" },
  "redirect_uri must appear exactly once.": {
    "zh-CN": "redirect_uri 必须且只能出现一次。",
    ja: "redirect_uriは1回だけ指定する必要があります。",
  },
  "Invalid redirect_uri.": { "zh-CN": "redirect_uri 无效。", ja: "redirect_uriが無効です。" },
  "Email delivery is unavailable": {
    "zh-CN": "电子邮件发送不可用",
    ja: "メール送信を利用できません",
  },
  "Email delivery failed": { "zh-CN": "电子邮件发送失败", ja: "メール送信に失敗しました" },
  "Signing key unavailable": { "zh-CN": "签名密钥不可用", ja: "署名鍵を利用できません" },
  "Signing key state changed concurrently": {
    "zh-CN": "签名密钥状态已被并发更改",
    ja: "署名鍵の状態が同時に変更されました",
  },
  "Pending signing key unavailable": {
    "zh-CN": "待处理签名密钥不可用",
    ja: "保留中の署名鍵を利用できません",
  },
  "Signing key rotation is already in progress": {
    "zh-CN": "签名密钥轮换已在进行中",
    ja: "署名鍵のローテーションはすでに進行中です",
  },
  "Signing key initialization is still in progress": {
    "zh-CN": "签名密钥初始化仍在进行中",
    ja: "署名鍵の初期化はまだ進行中です",
  },
  "This account is unavailable": { "zh-CN": "此账户不可用", ja: "このアカウントは利用できません" },
  "Upstream request failed": { "zh-CN": "上游请求失败", ja: "上流リクエストに失敗しました" },
  "Your KeyForge sign-in link": {
    "zh-CN": "您的 KeyForge 登录链接",
    ja: "KeyForge ログインリンク",
  },
  "Sign in to KeyForge:": { "zh-CN": "登录 KeyForge：", ja: "KeyForge にログイン：" },
  "This link expires in 15 minutes. If you did not request it, ignore this email.": {
    "zh-CN": "此链接将在 15 分钟后过期。如果并非您本人请求，请忽略此邮件。",
    ja: "このリンクの有効期限は15分です。心当たりがない場合は、このメールを無視してください。",
  },
  "Sign in to KeyForge by clicking the link below:": {
    "zh-CN": "点击以下链接登录 KeyForge：",
    ja: "以下のリンクをクリックして KeyForge にログインしてください：",
  },
  "This link expires in 15 minutes. If you did not request it, you can safely ignore this email.": {
    "zh-CN": "此链接将在 15 分钟后过期。如果并非您本人请求，可以安全地忽略此邮件。",
    ja: "このリンクの有効期限は15分です。心当たりがない場合は、このメールを無視して問題ありません。",
  },
  "Reset your KeyForge password": {
    "zh-CN": "重置您的 KeyForge 密码",
    ja: "KeyForge パスワードのリセット",
  },
  "Reset your KeyForge password:": {
    "zh-CN": "重置您的 KeyForge 密码：",
    ja: "KeyForge パスワードをリセット：",
  },
  "This link expires in one hour. If you did not request it, ignore this email.": {
    "zh-CN": "此链接将在一小时后过期。如果并非您本人请求，请忽略此邮件。",
    ja: "このリンクの有効期限は1時間です。心当たりがない場合は、このメールを無視してください。",
  },
  "Use the secure link below to reset your KeyForge password:": {
    "zh-CN": "使用以下安全链接重置您的 KeyForge 密码：",
    ja: "以下の安全なリンクから KeyForge パスワードをリセットしてください：",
  },
  "This link expires in one hour. If you did not request it, you can safely ignore this email.": {
    "zh-CN": "此链接将在一小时后过期。如果并非您本人请求，可以安全地忽略此邮件。",
    ja: "このリンクの有効期限は1時間です。心当たりがない場合は、このメールを無視して問題ありません。",
  },
  "You have been invited to KeyForge": {
    "zh-CN": "您已受邀加入 KeyForge",
    ja: "KeyForge に招待されました",
  },
  "An administrator created a KeyForge account for you. Set your password to accept the invitation:":
    {
      "zh-CN": "管理员已为您创建 KeyForge 账户。请设置密码以接受邀请：",
      ja: "管理者があなたの KeyForge アカウントを作成しました。パスワードを設定して招待を承諾してください：",
    },
  "This single-use link expires in one hour. If you were not expecting this invitation, ignore this email.":
    {
      "zh-CN": "此一次性链接将在一小时后过期。如果您并未期待此邀请，请忽略此邮件。",
      ja: "この1回限りのリンクの有効期限は1時間です。この招待に心当たりがない場合は、メールを無視してください。",
    },
  "An administrator created a KeyForge account for you.": {
    "zh-CN": "管理员已为您创建 KeyForge 账户。",
    ja: "管理者があなたの KeyForge アカウントを作成しました。",
  },
  "Set password and accept invitation": {
    "zh-CN": "设置密码并接受邀请",
    ja: "パスワードを設定して招待を承諾",
  },
  "This single-use link expires in one hour. If you were not expecting this invitation, you can safely ignore this email.":
    {
      "zh-CN": "此一次性链接将在一小时后过期。如果您并未期待此邀请，可以安全地忽略此邮件。",
      ja: "この1回限りのリンクの有効期限は1時間です。この招待に心当たりがない場合は、メールを無視して問題ありません。",
    },
  "Verify your KeyForge email": {
    "zh-CN": "验证您的 KeyForge 电子邮箱",
    ja: "KeyForge メールアドレスの確認",
  },
  "Verify your KeyForge email address:": {
    "zh-CN": "验证您的 KeyForge 电子邮箱地址：",
    ja: "KeyForge のメールアドレスを確認：",
  },
  "This link expires in 24 hours.": {
    "zh-CN": "此链接将在 24 小时后过期。",
    ja: "このリンクの有効期限は24時間です。",
  },
  "Confirm this email address for your KeyForge account:": {
    "zh-CN": "确认此地址为您的 KeyForge 账户电子邮箱：",
    ja: "このメールアドレスを KeyForge アカウント用として確認してください：",
  },
  "Confirm your new KeyForge email": {
    "zh-CN": "确认您的新 KeyForge 电子邮箱",
    ja: "KeyForge の新しいメールアドレスを確認",
  },
  "Confirm this as your new KeyForge email address:": {
    "zh-CN": "确认将此地址作为您的新 KeyForge 电子邮箱：",
    ja: "このアドレスを新しい KeyForge メールアドレスとして確認してください：",
  },
  "This single-use link expires in 24 hours. If you did not request this change, secure your account immediately.":
    {
      "zh-CN": "此一次性链接将在 24 小时后过期。如果并非您本人请求更改，请立即保护您的账户。",
      ja: "この1回限りのリンクの有効期限は24時間です。変更に心当たりがない場合は、直ちにアカウントを保護してください。",
    },
  "Confirm this as the new email address for your KeyForge account:": {
    "zh-CN": "确认将此地址作为您的 KeyForge 账户新电子邮箱：",
    ja: "このアドレスを KeyForge アカウントの新しいメールアドレスとして確認してください：",
  },
  "Confirm new email": { "zh-CN": "确认新电子邮箱", ja: "新しいメールアドレスを確認" },
  Profile: { "zh-CN": "个人资料", ja: "プロフィール" },
  "Login methods": { "zh-CN": "登录方式", ja: "ログイン方法" },
  "Active sessions": { "zh-CN": "活动会话", ja: "アクティブなセッション" },
  "Authorized apps": { "zh-CN": "已授权应用", ja: "承認済みアプリ" },
  Administration: { "zh-CN": "管理", ja: "管理" },
  "Your account": { "zh-CN": "您的账户", ja: "アカウント" },
  "Your account — KeyForge": { "zh-CN": "您的账户 — KeyForge", ja: "アカウント — KeyForge" },
  "Magic link": { "zh-CN": "魔法链接", ja: "マジックリンク" },
  Passkey: { "zh-CN": "通行密钥", ja: "パスキー" },
  Verified: { "zh-CN": "已验证", ja: "確認済み" },
  Unverified: { "zh-CN": "未验证", ja: "未確認" },
  "Send verification email": { "zh-CN": "发送验证邮件", ja: "確認メールを送信" },
  "Current password": { "zh-CN": "当前密码", ja: "現在のパスワード" },
  "A recent sign-in is required because this account has no password.": {
    "zh-CN": "此账户没有密码，因此需要近期登录验证。",
    ja: "このアカウントにはパスワードがないため、直近のログインが必要です。",
  },
  "Your account identity and information shared with approved applications.": {
    "zh-CN": "您的账户身份以及与已获准应用共享的信息。",
    ja: "アカウント情報と、承認済みアプリに共有される情報です。",
  },
  Username: { "zh-CN": "用户名", ja: "ユーザー名" },
  Verification: { "zh-CN": "验证状态", ja: "確認状態" },
  Groups: { "zh-CN": "群组", ja: "グループ" },
  "Member since": { "zh-CN": "加入时间", ja: "登録日" },
  "Public profile": { "zh-CN": "公开资料", ja: "公開プロフィール" },
  "Your username may contain only English letters and numbers.": {
    "zh-CN": "用户名只能包含英文字母和数字。",
    ja: "ユーザー名には英字と数字のみ使用できます。",
  },
  "Display name": { "zh-CN": "显示名称", ja: "表示名" },
  "Save profile": { "zh-CN": "保存资料", ja: "プロフィールを保存" },
  "Email verification": { "zh-CN": "电子邮箱验证", ja: "メールアドレスの確認" },
  "This address has been verified.": {
    "zh-CN": "此地址已验证。",
    ja: "このアドレスは確認済みです。",
  },
  "Verify this address before applications treat it as confirmed.": {
    "zh-CN": "请先验证此地址，应用才会将其视为已确认。",
    ja: "アプリで確認済みとして扱う前に、このアドレスを確認してください。",
  },
  "We confirm the new address before changing your sign-in email.": {
    "zh-CN": "更改登录电子邮箱前，我们会先确认新地址。",
    ja: "ログイン用メールアドレスを変更する前に、新しいアドレスを確認します。",
  },
  "New email": { "zh-CN": "新电子邮箱", ja: "新しいメールアドレス" },
  "Send confirmation": { "zh-CN": "发送确认邮件", ja: "確認メールを送信" },
  "Delete account": { "zh-CN": "删除账户", ja: "アカウントを削除" },
  "Permanently removes sessions, login methods, and application grants.": {
    "zh-CN": "永久移除会话、登录方式和应用授权。",
    ja: "セッション、ログイン方法、アプリへの許可を完全に削除します。",
  },
  "Type {value} to confirm": { "zh-CN": "输入 {value} 以确认", ja: "確認のため {value} と入力" },
  "Password name": { "zh-CN": "密码名称", ja: "パスワード名" },
  "Passkey name": { "zh-CN": "通行密钥名称", ja: "パスキー名" },
  Rename: { "zh-CN": "重命名", ja: "名前を変更" },
  Delete: { "zh-CN": "删除", ja: "削除" },
  Added: { "zh-CN": "添加于", ja: "追加日" },
  "Last used": { "zh-CN": "上次使用", ja: "最終使用" },
  "Not available for administrator sign-in": {
    "zh-CN": "不可用于管理员登录",
    ja: "管理者ログインには使用できません",
  },
  "You are adding the first password to this account. A recent sign-in is required.": {
    "zh-CN": "您正在为此账户添加第一个密码，需要近期登录验证。",
    ja: "このアカウントに最初のパスワードを追加します。直近のログインが必要です。",
  },
  "Passwords and passkeys are independent ways to access this account. Add more than one for recovery.":
    {
      "zh-CN": "密码和通行密钥是访问此账户的独立方式。建议添加多种方式以便恢复。",
      ja: "パスワードとパスキーは独立したログイン方法です。復旧に備えて複数追加してください。",
    },
  "Add passkey": { "zh-CN": "添加通行密钥", ja: "パスキーを追加" },
  "No reusable login methods yet. Add a password or passkey.": {
    "zh-CN": "尚无可重复使用的登录方式。请添加密码或通行密钥。",
    ja: "再利用可能なログイン方法がありません。パスワードまたはパスキーを追加してください。",
  },
  "Add a password": { "zh-CN": "添加密码", ja: "パスワードを追加" },
  "Use {minimum}–128 characters.": {
    "zh-CN": "请使用 {minimum}–128 个字符。",
    ja: "{minimum}〜128文字で入力してください。",
  },
  "Use {minimum}–128 characters; administrator passwords require at least 12.": {
    "zh-CN": "请使用 {minimum}–128 个字符；管理员密码至少需要 12 个字符。",
    ja: "{minimum}〜128文字で入力してください。管理者のパスワードは12文字以上必要です。",
  },
  Name: { "zh-CN": "名称", ja: "名前" },
  "e.g. Password manager": { "zh-CN": "例如：密码管理器", ja: "例：パスワードマネージャー" },
  "Confirm password": { "zh-CN": "确认密码", ja: "パスワードを確認" },
  "Add password": { "zh-CN": "添加密码", ja: "パスワードを追加" },
  "Follow your browser's passkey prompt…": {
    "zh-CN": "请按照浏览器的通行密钥提示操作…",
    ja: "ブラウザーのパスキー画面に従ってください…",
  },
  "Passkey creation was cancelled.": {
    "zh-CN": "通行密钥创建已取消。",
    ja: "パスキーの作成はキャンセルされました。",
  },
  "Passkey creation could not be completed.": {
    "zh-CN": "无法完成通行密钥创建。",
    ja: "パスキーの作成を完了できませんでした。",
  },
  "This device": { "zh-CN": "此设备", ja: "このデバイス" },
  Started: { "zh-CN": "开始于", ja: "開始" },
  "Last active": { "zh-CN": "上次活动", ja: "最終アクティブ" },
  Expires: { "zh-CN": "到期", ja: "有効期限" },
  "Devices and browsers currently signed in to your account.": {
    "zh-CN": "当前已登录您账户的设备和浏览器。",
    ja: "現在アカウントにログインしているデバイスとブラウザーです。",
  },
  "Sign out all other sessions": {
    "zh-CN": "退出所有其他会话",
    ja: "他のすべてのセッションからログアウト",
  },
  "Resources:": { "zh-CN": "资源：", ja: "リソース：" },
  "Revoke all access": { "zh-CN": "撤销所有访问权限", ja: "すべてのアクセスを取り消す" },
  "Revoke device": { "zh-CN": "撤销设备", ja: "デバイスを取り消す" },
  "Applications you have granted access to your account.": {
    "zh-CN": "您已允许访问账户的应用。",
    ja: "アカウントへのアクセスを許可したアプリです。",
  },
  "No applications currently have access.": {
    "zh-CN": "当前没有应用拥有访问权限。",
    ja: "現在アクセス権を持つアプリはありません。",
  },
  "Authorized CLI and devices": { "zh-CN": "已授权的 CLI 和设备", ja: "承認済みの CLI とデバイス" },
  "Refresh access issued independently to a device.": {
    "zh-CN": "单独向设备签发的刷新访问权限。",
    ja: "デバイスに個別に発行された更新アクセスです。",
  },
  "No independently authorized device sessions.": {
    "zh-CN": "没有独立授权的设备会话。",
    ja: "個別に承認されたデバイスセッションはありません。",
  },
  "Configure applications, users, resources, devices, and audit activity.": {
    "zh-CN": "配置应用、用户、资源、设备和审计活动。",
    ja: "アプリ、ユーザー、リソース、デバイス、監査アクティビティを設定します。",
  },
  "Open admin console": { "zh-CN": "打开管理控制台", ja: "管理コンソールを開く" },
  "Profile saved.": { "zh-CN": "个人资料已保存。", ja: "プロフィールを保存しました。" },
  "Choose an available username using only English letters and numbers.": {
    "zh-CN": "请选择一个仅含英文字母和数字的可用用户名。",
    ja: "英字と数字のみを使った、利用可能なユーザー名を選んでください。",
  },
  "Password added.": { "zh-CN": "密码已添加。", ja: "パスワードを追加しました。" },
  "Password renamed.": { "zh-CN": "密码已重命名。", ja: "パスワード名を変更しました。" },
  "Password deleted.": { "zh-CN": "密码已删除。", ja: "パスワードを削除しました。" },
  "Check the current password, new password policy, and confirmation.": {
    "zh-CN": "请检查当前密码、新密码策略及确认内容。",
    ja: "現在のパスワード、新しいパスワードのポリシー、確認入力を確認してください。",
  },
  "Verification email sent.": { "zh-CN": "验证邮件已发送。", ja: "確認メールを送信しました。" },
  "Your email is already verified.": {
    "zh-CN": "您的电子邮箱已验证。",
    ja: "メールアドレスはすでに確認済みです。",
  },
  "Email delivery is temporarily unavailable.": {
    "zh-CN": "电子邮件发送暂时不可用。",
    ja: "メール送信は一時的に利用できません。",
  },
  "Check the new address to confirm your email change.": {
    "zh-CN": "请查收新地址的邮件以确认更改。",
    ja: "新しいアドレスのメールを確認して変更を確定してください。",
  },
  "Check the new email and current password, then try again.": {
    "zh-CN": "请检查新电子邮箱和当前密码，然后重试。",
    ja: "新しいメールアドレスと現在のパスワードを確認して、もう一度お試しください。",
  },
  "Passkey added.": { "zh-CN": "通行密钥已添加。", ja: "パスキーを追加しました。" },
  "Passkey renamed.": { "zh-CN": "通行密钥已重命名。", ja: "パスキー名を変更しました。" },
  "Passkey deleted.": { "zh-CN": "通行密钥已删除。", ja: "パスキーを削除しました。" },
  "Device access revoked.": {
    "zh-CN": "设备访问权限已撤销。",
    ja: "デバイスのアクセスを取り消しました。",
  },
  "Add another password or passkey before removing this one.": {
    "zh-CN": "请先添加另一个密码或通行密钥，再移除此项。",
    ja: "これを削除する前に、別のパスワードまたはパスキーを追加してください。",
  },
  "Account deletion confirmation did not match.": {
    "zh-CN": "账户删除确认内容不匹配。",
    ja: "アカウント削除の確認入力が一致しません。",
  },
  "Assign another active administrator before deleting this account.": {
    "zh-CN": "删除此账户前，请先指定另一名活动管理员。",
    ja: "このアカウントを削除する前に、別の有効な管理者を割り当ててください。",
  },
  "The request could not be verified.": {
    "zh-CN": "无法验证此请求。",
    ja: "リクエストを確認できませんでした。",
  },
  "That item no longer exists.": { "zh-CN": "该项目已不存在。", ja: "その項目は存在しません。" },
  Overview: { "zh-CN": "概览", ja: "概要" },
  Users: { "zh-CN": "用户", ja: "ユーザー" },
  Applications: { "zh-CN": "应用", ja: "アプリケーション" },
  APIs: { "zh-CN": "API", ja: "API" },
  Devices: { "zh-CN": "设备", ja: "デバイス" },
  "Audit log": { "zh-CN": "审计日志", ja: "監査ログ" },
  "A guided view of your identity service and the next useful setup step.": {
    "zh-CN": "身份服务的引导式概览，以及下一项实用设置步骤。",
    ja: "IDサービスの概要と、次に行うべき設定手順を案内します。",
  },
  "Provision people, organize access groups, and manage their login methods.": {
    "zh-CN": "配置人员、组织访问群组并管理其登录方式。",
    ja: "ユーザーの作成、アクセスグループの整理、ログイン方法の管理を行います。",
  },
  "Register applications and configure OAuth flows without missing required settings.": {
    "zh-CN": "注册应用并完整配置 OAuth 流程所需设置。",
    ja: "必要な設定を漏らさず、アプリの登録と OAuth フローの設定を行います。",
  },
  "Define API audiences and the scopes applications may request.": {
    "zh-CN": "定义 API 受众以及应用可请求的作用域。",
    ja: "APIの対象（audience）と、アプリが要求できるスコープを定義します。",
  },
  "Review and revoke device authorization sessions.": {
    "zh-CN": "查看和撤销设备授权会话。",
    ja: "デバイス承認セッションの確認と取り消しを行います。",
  },
  "Trace administrative changes, sign-ins, and OAuth security events.": {
    "zh-CN": "追踪管理变更、登录和 OAuth 安全事件。",
    ja: "管理上の変更、ログイン、OAuthセキュリティイベントを追跡します。",
  },
  "Access denied": { "zh-CN": "访问被拒绝", ja: "アクセスが拒否されました" },
  "Your account doesn't have administrator access.": {
    "zh-CN": "您的账户没有管理员访问权限。",
    ja: "このアカウントには管理者権限がありません。",
  },
  "Back to your account": { "zh-CN": "返回账户", ja: "アカウントに戻る" },
  "Access denied — KeyForge": {
    "zh-CN": "访问被拒绝 — KeyForge",
    ja: "アクセス拒否 — KeyForge",
  },
  "Signed in as": { "zh-CN": "登录身份", ja: "ログイン中" },
  "Admin console": { "zh-CN": "管理控制台", ja: "管理コンソール" },
  "No results on this page.": { "zh-CN": "此页没有结果。", ja: "このページに結果はありません。" },
  "Showing {start}–{end}": { "zh-CN": "显示 {start}–{end}", ja: "{start}〜{end}件を表示" },
  Previous: { "zh-CN": "上一页", ja: "前へ" },
  Next: { "zh-CN": "下一页", ja: "次へ" },
  "OAuth clients": { "zh-CN": "OAuth 客户端", ja: "OAuthクライアント" },
  Resources: { "zh-CN": "资源", ja: "リソース" },
  "Device sessions": { "zh-CN": "设备会话", ja: "デバイスセッション" },
  "Register an application": { "zh-CN": "注册应用", ja: "アプリケーションを登録" },
  "Choose an OAuth flow and configure callback URLs.": {
    "zh-CN": "选择 OAuth 流程并配置回调 URL。",
    ja: "OAuthフローを選択し、コールバックURLを設定します。",
  },
  "Create application": { "zh-CN": "创建应用", ja: "アプリケーションを作成" },
  "Provision your first user": { "zh-CN": "配置首位用户", ja: "最初のユーザーを作成" },
  "Create a username and choose password, invitation, and group access.": {
    "zh-CN": "创建用户名，并选择密码、邀请和群组访问权限。",
    ja: "ユーザー名を作成し、パスワード、招待、グループアクセスを設定します。",
  },
  "Add user": { "zh-CN": "添加用户", ja: "ユーザーを追加" },
  "Define an API": { "zh-CN": "定义 API", ja: "APIを定義" },
  "Register an audience and the scopes applications may request.": {
    "zh-CN": "注册受众以及应用可请求的作用域。",
    ja: "対象（audience）とアプリが要求できるスコープを登録します。",
  },
  "Create API": { "zh-CN": "创建 API", ja: "APIを作成" },
  "Review security activity": { "zh-CN": "查看安全活动", ja: "セキュリティ活動を確認" },
  "Use the audit log to verify setup and sign-in events.": {
    "zh-CN": "使用审计日志验证设置和登录事件。",
    ja: "監査ログで設定とログインイベントを確認します。",
  },
  "Open audit log": { "zh-CN": "打开审计日志", ja: "監査ログを開く" },
  Review: { "zh-CN": "查看", ja: "確認" },
  "Your workspace is ready": {
    "zh-CN": "您的工作区已就绪",
    ja: "ワークスペースの準備ができました",
  },
  "Get KeyForge ready": { "zh-CN": "完成 KeyForge 设置", ja: "KeyForge をセットアップ" },
  "Core configuration is in place. Revisit any step when your integration changes.": {
    "zh-CN": "核心配置已就绪。集成发生变化时，可重新检查任一步骤。",
    ja: "基本設定は完了しています。連携内容が変わった場合は、各手順を見直してください。",
  },
  "Follow these steps to move from a new tenant to a working sign-in flow.": {
    "zh-CN": "按照以下步骤，将新租户配置为可用的登录流程。",
    ja: "以下の手順で、新しいテナントから動作するログインフローまで設定します。",
  },
  "Setup progress": { "zh-CN": "设置进度", ja: "セットアップの進捗" },
  "{completed} of {total} steps complete": {
    "zh-CN": "已完成 {completed}/{total} 步",
    ja: "{total}ステップ中{completed}ステップ完了",
  },
  "Recent activity": { "zh-CN": "最近活动", ja: "最近のアクティビティ" },
  "The latest security events across the server.": {
    "zh-CN": "服务器范围内最新的安全事件。",
    ja: "サーバー全体の最新セキュリティイベントです。",
  },
  "View all": { "zh-CN": "查看全部", ja: "すべて表示" },
  Time: { "zh-CN": "时间", ja: "時刻" },
  Event: { "zh-CN": "事件", ja: "イベント" },
  Result: { "zh-CN": "结果", ja: "結果" },
  Actor: { "zh-CN": "操作者", ja: "実行者" },
  "Subject user": { "zh-CN": "目标用户", ja: "対象ユーザー" },
  "No activity recorded yet.": {
    "zh-CN": "尚未记录活动。",
    ja: "記録されたアクティビティはありません。",
  },
  ok: { "zh-CN": "成功", ja: "成功" },
  fail: { "zh-CN": "失败", ja: "失敗" },
  Revoke: { "zh-CN": "撤销", ja: "取り消す" },
  pending: { "zh-CN": "待处理", ja: "保留中" },
  approved: { "zh-CN": "已批准", ja: "承認済み" },
  denied: { "zh-CN": "已拒绝", ja: "拒否済み" },
  expired: { "zh-CN": "已过期", ja: "期限切れ" },
  consumed: { "zh-CN": "已使用", ja: "使用済み" },
  "Device authorization grants and their current status.": {
    "zh-CN": "设备授权许可及其当前状态。",
    ja: "デバイス承認グラントと現在の状態です。",
  },
  Client: { "zh-CN": "客户端", ja: "クライアント" },
  Status: { "zh-CN": "状态", ja: "状態" },
  User: { "zh-CN": "用户", ja: "ユーザー" },
  "No device sessions.": { "zh-CN": "没有设备会话。", ja: "デバイスセッションはありません。" },
  "Every security-relevant event, newest first.": {
    "zh-CN": "所有安全相关事件，按时间倒序排列。",
    ja: "セキュリティ関連の全イベントを新しい順に表示します。",
  },
  "Event type": { "zh-CN": "事件类型", ja: "イベント種別" },
  "User ID": { "zh-CN": "用户 ID", ja: "ユーザーID" },
  "Client ID": { "zh-CN": "客户端 ID", ja: "クライアントID" },
  "Actor user ID": { "zh-CN": "操作者用户 ID", ja: "実行ユーザーID" },
  "Actor client ID": { "zh-CN": "操作者客户端 ID", ja: "実行クライアントID" },
  Clear: { "zh-CN": "清除", ja: "クリア" },
  "Actor user": { "zh-CN": "操作者用户", ja: "実行ユーザー" },
  "Actor client": { "zh-CN": "操作者客户端", ja: "実行クライアント" },
  "Subject client": { "zh-CN": "目标客户端", ja: "対象クライアント" },
  Detail: { "zh-CN": "详情", ja: "詳細" },
  "No matching events.": { "zh-CN": "没有匹配的事件。", ja: "一致するイベントはありません。" },
  Enabled: { "zh-CN": "已启用", ja: "有効" },
  Disabled: { "zh-CN": "已禁用", ja: "無効" },
  Edit: { "zh-CN": "编辑", ja: "編集" },
  "Protected APIs (audiences) that tokens can be issued for.": {
    "zh-CN": "可签发令牌的受保护 API（受众）。",
    ja: "トークンを発行できる保護対象API（audience）です。",
  },
  "New resource": { "zh-CN": "新建资源", ja: "新しいリソース" },
  "Resource URI": { "zh-CN": "资源 URI", ja: "リソースURI" },
  Scopes: { "zh-CN": "作用域", ja: "スコープ" },
  "No resources yet.": { "zh-CN": "尚无资源。", ja: "リソースはまだありません。" },
  "Register a protected API.": { "zh-CN": "注册受保护的 API。", ja: "保護対象APIを登録します。" },
  "Edit resource configuration.": { "zh-CN": "编辑资源配置。", ja: "リソース設定を編集します。" },
  "Back to resources": { "zh-CN": "返回资源", ja: "リソース一覧に戻る" },
  "Allowed scopes": { "zh-CN": "允许的作用域", ja: "許可するスコープ" },
  "One scope per line.": { "zh-CN": "每行一个作用域。", ja: "1行に1つのスコープを入力します。" },
  "Create resource": { "zh-CN": "创建资源", ja: "リソースを作成" },
  "Save changes": { "zh-CN": "保存更改", ja: "変更を保存" },
  Active: { "zh-CN": "活动", ja: "有効" },
  Manage: { "zh-CN": "管理", ja: "管理" },
  "Group name": { "zh-CN": "群组名称", ja: "グループ名" },
  "Group description": { "zh-CN": "群组描述", ja: "グループの説明" },
  Save: { "zh-CN": "保存", ja: "保存" },
  Protected: { "zh-CN": "受保护", ja: "保護対象" },
  "Identity directory": { "zh-CN": "身份目录", ja: "IDディレクトリ" },
  "Create accounts, invite people, and assign access groups.": {
    "zh-CN": "创建账户、邀请人员并分配访问群组。",
    ja: "アカウントの作成、ユーザーの招待、アクセスグループの割り当てを行います。",
  },
  "Everyone who can sign in to this server.": {
    "zh-CN": "所有可以登录此服务器的人员。",
    ja: "このサーバーにログインできるすべてのユーザーです。",
  },
  Created: { "zh-CN": "创建时间", ja: "作成日" },
  "No users found. Add the first account to begin.": {
    "zh-CN": "未找到用户。请添加第一个账户。",
    ja: "ユーザーが見つかりません。最初のアカウントを追加してください。",
  },
  "Permission groups": { "zh-CN": "权限群组", ja: "権限グループ" },
  "Use groups to grant application and administrator claims.": {
    "zh-CN": "使用群组授予应用和管理员声明。",
    ja: "グループを使って、アプリや管理者向けのクレームを付与します。",
  },
  Group: { "zh-CN": "群组", ja: "グループ" },
  Members: { "zh-CN": "成员", ja: "メンバー" },
  "No groups found. Create one below.": {
    "zh-CN": "未找到群组。请在下方创建一个。",
    ja: "グループが見つかりません。下から作成してください。",
  },
  Description: { "zh-CN": "描述", ja: "説明" },
  "What membership grants": { "zh-CN": "成员身份授予的权限", ja: "メンバーシップで付与する内容" },
  "Create group": { "zh-CN": "创建群组", ja: "グループを作成" },
  "No groups exist yet. Create one from the user directory.": {
    "zh-CN": "尚无群组。请从身份目录创建。",
    ja: "グループはまだありません。ユーザーディレクトリから作成してください。",
  },
  "No description": { "zh-CN": "无描述", ja: "説明なし" },
  "Delete permission group?": { "zh-CN": "删除权限群组？", ja: "権限グループを削除しますか？" },
  "{group} currently has {count} member.": {
    "zh-CN": "{group} 当前有 {count} 名成员。",
    ja: "{group} には現在{count}人のメンバーがいます。",
  },
  "{group} currently has {count} members.": {
    "zh-CN": "{group} 当前有 {count} 名成员。",
    ja: "{group} には現在{count}人のメンバーがいます。",
  },
  "Confirm group deletion": { "zh-CN": "确认删除群组", ja: "グループ削除の確認" },
  "This permanently removes the group and every membership assignment. User accounts are not deleted.":
    {
      "zh-CN": "这将永久移除该群组及所有成员分配，但不会删除用户账户。",
      ja: "グループとすべてのメンバー割り当てを完全に削除します。ユーザーアカウントは削除されません。",
    },
  "Delete group": { "zh-CN": "删除群组", ja: "グループを削除" },
  "Delete group?": { "zh-CN": "删除群组？", ja: "グループを削除しますか？" },
  "Add a user": { "zh-CN": "添加用户", ja: "ユーザーを追加" },
  "Give someone a direct credential or send a single-use invitation.": {
    "zh-CN": "为用户提供直接凭据，或发送一次性邀请。",
    ja: "直接使える認証情報を設定するか、1回限りの招待を送信します。",
  },
  "Back to users": { "zh-CN": "返回用户", ja: "ユーザー一覧に戻る" },
  "Account details": { "zh-CN": "账户详情", ja: "アカウントの詳細" },
  "Leaving the password blank sends a secure one-hour invitation link.": {
    "zh-CN": "密码留空时，会发送有效期一小时的安全邀请链接。",
    ja: "パスワードを空欄にすると、有効期限1時間の安全な招待リンクを送信します。",
  },
  "English letters and numbers only; usernames are unique and can be used at sign-in.": {
    "zh-CN": "仅限英文字母和数字；用户名唯一，并可用于登录。",
    ja: "英字と数字のみ使用できます。ユーザー名は一意で、ログインにも使用できます。",
  },
  Optional: { "zh-CN": "可选", ja: "任意" },
  "Initial password": { "zh-CN": "初始密码", ja: "初期パスワード" },
  "Leave blank to send an invitation": { "zh-CN": "留空以发送邀请", ja: "空欄にすると招待を送信" },
  "Initial passwords require 6–128 characters, or at least 12 when the admins group is selected. Invitations never expose a credential to the administrator.":
    {
      "zh-CN":
        "初始密码需要 6–128 个字符；选择 admins 群组时至少需要 12 个字符。邀请不会向管理员暴露凭据。",
      ja: "初期パスワードは6〜128文字、adminsグループを選択した場合は12文字以上必要です。招待では管理者に認証情報が開示されません。",
    },
  "Mark email as verified": { "zh-CN": "将电子邮箱标记为已验证", ja: "メールを確認済みにする" },
  "Create user": { "zh-CN": "创建用户", ja: "ユーザーを作成" },
  "Unavailable while this user is an administrator": {
    "zh-CN": "此用户为管理员时不可用",
    ja: "このユーザーが管理者の間は利用できません",
  },
  Never: { "zh-CN": "从未", ja: "未使用" },
  "Groups:": { "zh-CN": "群组：", ja: "グループ：" },
  "English letters and numbers only. Users can sign in with this username.": {
    "zh-CN": "仅限英文字母和数字。用户可以使用此用户名登录。",
    ja: "英字と数字のみ使用できます。ユーザーはこのユーザー名でログインできます。",
  },
  "No name set": { "zh-CN": "未设置名称", ja: "名前未設定" },
  "Account disabled (blocks sign-in)": {
    "zh-CN": "账户已禁用（阻止登录）",
    ja: "アカウントを無効化（ログインをブロック）",
  },
  "Passwords and passkeys are managed together. Keep at least one reusable method.": {
    "zh-CN": "密码和通行密钥统一管理。请至少保留一种可重复使用的方式。",
    ja: "パスワードとパスキーはまとめて管理されます。再利用可能な方法を1つ以上残してください。",
  },
  "{count} total": { "zh-CN": "共 {count} 个", ja: "合計{count}件" },
  Type: { "zh-CN": "类型", ja: "種類" },
  "No password or passkey has been configured.": {
    "zh-CN": "尚未配置密码或通行密钥。",
    ja: "パスワードまたはパスキーが設定されていません。",
  },
  "e.g. Temporary password": { "zh-CN": "例如：临时密码", ja: "例：一時パスワード" },
  "Requires {minimum}–128 characters for this user. Password values are never shown again.": {
    "zh-CN": "此用户的密码需要 {minimum}–128 个字符。密码值不会再次显示。",
    ja: "このユーザーのパスワードは{minimum}〜128文字必要です。パスワードは再表示されません。",
  },
  "Generate a one-time 15-minute sign-in link for this existing user.": {
    "zh-CN": "为此现有用户生成有效期 15 分钟的一次性登录链接。",
    ja: "このユーザー用に、有効期限15分の1回限りのログインリンクを生成します。",
  },
  "Generate magic link": { "zh-CN": "生成魔法链接", ja: "マジックリンクを生成" },
  "Enable this user before generating a sign-in link.": {
    "zh-CN": "生成登录链接前，请先启用此用户。",
    ja: "ログインリンクを生成する前に、このユーザーを有効にしてください。",
  },
  "Group access": { "zh-CN": "群组访问权限", ja: "グループアクセス" },
  "Administrator access comes from the admins group. The last active administrator cannot remove it.":
    {
      "zh-CN": "管理员访问权限来自 admins 群组。最后一名活动管理员不能移除此权限。",
      ja: "管理者権限はadminsグループから付与されます。最後の有効な管理者からは削除できません。",
    },
  "Update groups": { "zh-CN": "更新群组", ja: "グループを更新" },
  Sessions: { "zh-CN": "会话", ja: "セッション" },
  "Force sign-out on every device this user is signed in on.": {
    "zh-CN": "强制退出此用户已登录的所有设备。",
    ja: "このユーザーがログインしているすべてのデバイスから強制ログアウトします。",
  },
  "Revoke all sessions": { "zh-CN": "撤销所有会话", ja: "すべてのセッションを取り消す" },
  "Magic link generated": { "zh-CN": "魔法链接已生成", ja: "マジックリンクを生成しました" },
  "One-time sign-in for {email}.": {
    "zh-CN": "{email} 的一次性登录。",
    ja: "{email} 用の1回限りのログインです。",
  },
  "Back to user": { "zh-CN": "返回用户", ja: "ユーザーに戻る" },
  "Share this link securely": { "zh-CN": "安全地分享此链接", ja: "このリンクを安全に共有" },
  "It expires in 15 minutes and can be used only once. Creating another security transition invalidates it.":
    {
      "zh-CN": "链接将在 15 分钟后过期，且只能使用一次。创建其他安全操作会使其失效。",
      ja: "有効期限は15分で、1回のみ使用できます。別のセキュリティ操作を行うと無効になります。",
    },
  "The link is intentionally shown only on this page.": {
    "zh-CN": "出于安全考虑，此链接只在本页显示。",
    ja: "このリンクは意図的にこのページだけに表示されています。",
  },
  Public: { "zh-CN": "公共", ja: "パブリック" },
  Confidential: { "zh-CN": "机密", ja: "コンフィデンシャル" },
  Application: { "zh-CN": "应用", ja: "アプリケーション" },
  Device: { "zh-CN": "设备", ja: "デバイス" },
  Service: { "zh-CN": "服务", ja: "サービス" },
  "Interactive apps, devices, and services that trust this authorization server.": {
    "zh-CN": "信任此授权服务器的交互式应用、设备和服务。",
    ja: "この認可サーバーを信頼する対話型アプリ、デバイス、サービスです。",
  },
  Kind: { "zh-CN": "类别", ja: "種別" },
  "No clients yet.": { "zh-CN": "尚无客户端。", ja: "クライアントはまだありません。" },
  "One per line. e.g. authorization_code, refresh_token, client_credentials, urn:ietf:params:oauth:grant-type:device_code":
    {
      "zh-CN":
        "每行一个。例如 authorization_code、refresh_token、client_credentials、urn:ietf:params:oauth:grant-type:device_code",
      ja: "1行に1つ入力します。例：authorization_code、refresh_token、client_credentials、urn:ietf:params:oauth:grant-type:device_code",
    },
  "No enabled APIs are available.": {
    "zh-CN": "没有可用的已启用 API。",
    ja: "利用可能な有効なAPIがありません。",
  },
  "Create an API first": { "zh-CN": "请先创建 API", ja: "先にAPIを作成" },
  "Login flow": { "zh-CN": "登录流程", ja: "ログインフロー" },
  Access: { "zh-CN": "访问权限", ja: "アクセス" },
  "Create an application": { "zh-CN": "创建应用", ja: "アプリケーションを作成" },
  "New application": { "zh-CN": "新建应用", ja: "新しいアプリケーション" },
  "A guided setup for the OAuth flow, redirect URLs, and API access.": {
    "zh-CN": "引导您设置 OAuth 流程、重定向 URL 和 API 访问权限。",
    ja: "OAuthフロー、リダイレクトURL、APIアクセスを順に設定します。",
  },
  "Application setup": { "zh-CN": "应用设置", ja: "アプリケーション設定" },
  "Tell us what you're building": { "zh-CN": "告诉我们您要构建什么", ja: "構築するものを選択" },
  "These choices determine the safest OAuth flow. You can tune advanced settings after creation.": {
    "zh-CN": "这些选择会确定最安全的 OAuth 流程。创建后仍可调整高级设置。",
    ja: "選択内容に応じて最も安全なOAuthフローを決定します。作成後に詳細設定を調整できます。",
  },
  "Application name": { "zh-CN": "应用名称", ja: "アプリケーション名" },
  "Customer portal": { "zh-CN": "客户门户", ja: "カスタマーポータル" },
  "Application kind": { "zh-CN": "应用类别", ja: "アプリケーション種別" },
  "Web application": { "zh-CN": "Web 应用", ja: "Webアプリケーション" },
  "Interactive browser sign-in with authorization code and PKCE.": {
    "zh-CN": "使用授权码和 PKCE 的交互式浏览器登录。",
    ja: "認可コードとPKCEを使った対話型ブラウザーログインです。",
  },
  "Device or CLI": { "zh-CN": "设备或 CLI", ja: "デバイスまたはCLI" },
  "Input-constrained devices using the OAuth device authorization grant.": {
    "zh-CN": "使用 OAuth 设备授权许可的输入受限设备。",
    ja: "OAuthデバイス認可グラントを使用する、入力に制約のあるデバイスです。",
  },
  "Machine to machine": { "zh-CN": "机器到机器", ja: "マシン間通信" },
  "A backend service authenticating without a person.": {
    "zh-CN": "无需人员参与即可进行身份验证的后端服务。",
    ja: "人を介さずに認証するバックエンドサービスです。",
  },
  "Client authentication": { "zh-CN": "客户端身份验证", ja: "クライアント認証" },
  "No stored secret. Best for browser, mobile, desktop, and CLI clients.": {
    "zh-CN": "不存储密钥，适合浏览器、移动端、桌面端和 CLI 客户端。",
    ja: "シークレットを保存しません。ブラウザー、モバイル、デスクトップ、CLIに適しています。",
  },
  "Receives a one-time client secret for a trusted backend.": {
    "zh-CN": "为受信任的后端接收一次性显示的客户端密钥。",
    ja: "信頼できるバックエンド向けに、1回だけ表示されるクライアントシークレットを受け取ります。",
  },
  "Configure the login flow": { "zh-CN": "配置登录流程", ja: "ログインフローを設定" },
  "Callback URLs must match exactly. Local loopback HTTP is allowed for development.": {
    "zh-CN": "回调 URL 必须完全匹配。开发环境允许本地回环 HTTP。",
    ja: "コールバックURLは完全一致する必要があります。開発用のローカルループバックHTTPは許可されます。",
  },
  "Redirect URIs": { "zh-CN": "重定向 URI", ja: "リダイレクトURI" },
  "One exact callback URL per line.": {
    "zh-CN": "每行一个精确的回调 URL。",
    ja: "1行に1つ、完全一致するコールバックURLを入力します。",
  },
  "Post-logout redirect URIs": {
    "zh-CN": "退出后的重定向 URI",
    ja: "ログアウト後のリダイレクトURI",
  },
  "Where users may return after RP-Initiated Logout.": {
    "zh-CN": "用户在 RP 发起的退出登录后可返回的位置。",
    ja: "RP起点ログアウト後にユーザーが戻れる場所です。",
  },
  "Choose access": { "zh-CN": "选择访问权限", ja: "アクセスを選択" },
  "Grant only the scopes and API audiences this application needs.": {
    "zh-CN": "仅授予此应用需要的作用域和 API 受众。",
    ja: "このアプリに必要なスコープとAPIの対象（audience）のみを許可します。",
  },
  "One scope per line, such as openid, profile, or api.read.": {
    "zh-CN": "每行一个作用域，例如 openid、profile 或 api.read。",
    ja: "openid、profile、api.readなど、1行に1つのスコープを入力します。",
  },
  "Allowed grant types": { "zh-CN": "允许的许可类型", ja: "許可するグラントタイプ" },
  "Choose at least one enabled API. The wizard suggests one whose scopes match the selected application kind.":
    {
      "zh-CN": "至少选择一个已启用的 API。向导会建议作用域与所选应用类别匹配的 API。",
      ja: "有効なAPIを1つ以上選択してください。選択したアプリ種別に合うスコープのAPIが提案されます。",
    },
  "Default resource": { "zh-CN": "默认资源", ja: "デフォルトリソース" },
  "Review and create": { "zh-CN": "检查并创建", ja: "確認して作成" },
  "Check the important values before registering the application. Authorization-code clients always use S256 PKCE.":
    {
      "zh-CN": "注册应用前请检查重要值。授权码客户端始终使用 S256 PKCE。",
      ja: "アプリ登録前に重要な値を確認してください。認可コードクライアントは常にS256 PKCEを使用します。",
    },
  Authentication: { "zh-CN": "身份验证", ja: "認証" },
  "Grant types": { "zh-CN": "许可类型", ja: "グラントタイプ" },
  Back: { "zh-CN": "返回", ja: "戻る" },
  "Confidential (gets a secret)": {
    "zh-CN": "机密（获得密钥）",
    ja: "コンフィデンシャル（シークレットあり）",
  },
  "Type:": { "zh-CN": "类型：", ja: "種類：" },
  "Kind:": { "zh-CN": "类别：", ja: "種別：" },
  "Secret:": { "zh-CN": "密钥：", ja: "シークレット：" },
  none: { "zh-CN": "无", ja: "なし" },
  set: { "zh-CN": "已设置", ja: "設定済み" },
  "New client": { "zh-CN": "新建客户端", ja: "新しいクライアント" },
  "Register an OAuth client.": {
    "zh-CN": "注册 OAuth 客户端。",
    ja: "OAuthクライアントを登録します。",
  },
  "Edit client configuration.": {
    "zh-CN": "编辑客户端配置。",
    ja: "クライアント設定を編集します。",
  },
  "Back to applications": { "zh-CN": "返回应用", ja: "アプリケーション一覧に戻る" },
  "One URL per line.": { "zh-CN": "每行一个 URL。", ja: "1行に1つのURLを入力します。" },
  "Exact RP-Initiated Logout destinations, one per line.": {
    "zh-CN": "每行一个精确的 RP 发起退出登录目标地址。",
    ja: "RP起点ログアウトの遷移先を、1行に1つ完全一致で入力します。",
  },
  "Allowed resources": { "zh-CN": "允许的资源", ja: "許可するリソース" },
  "Resource URIs, one per line.": {
    "zh-CN": "每行一个资源 URI。",
    ja: "1行に1つのリソースURIを入力します。",
  },
  "Authorization-code clients always require PKCE with S256.": {
    "zh-CN": "授权码客户端始终需要使用 S256 的 PKCE。",
    ja: "認可コードクライアントでは常にS256のPKCEが必要です。",
  },
  "Create client": { "zh-CN": "创建客户端", ja: "クライアントを作成" },
  Disable: { "zh-CN": "禁用", ja: "無効化" },
  Enable: { "zh-CN": "启用", ja: "有効化" },
  "Rotate secret": { "zh-CN": "轮换密钥", ja: "シークレットをローテーション" },
  "Enable, disable, rotate the secret, or delete this client.": {
    "zh-CN": "启用、禁用、轮换密钥或删除此客户端。",
    ja: "このクライアントの有効化、無効化、シークレットのローテーション、削除を行います。",
  },
  "Delete client": { "zh-CN": "删除客户端", ja: "クライアントを削除" },
  "Delete OAuth client?": {
    "zh-CN": "删除 OAuth 客户端？",
    ja: "OAuthクライアントを削除しますか？",
  },
  "Rotate client secret?": {
    "zh-CN": "轮换客户端密钥？",
    ja: "クライアントシークレットをローテーションしますか？",
  },
  "This permanently removes the client, its grants, consents, and refresh tokens. Applications using it will stop working.":
    {
      "zh-CN": "这将永久移除客户端、其许可、同意和刷新令牌。使用它的应用将停止工作。",
      ja: "クライアント、そのグラント、同意、リフレッシュトークンを完全に削除します。使用中のアプリは動作しなくなります。",
    },
  "The current secret stops working immediately. Update the application with the new secret before it makes another request.":
    {
      "zh-CN": "当前密钥会立即失效。应用再次发出请求前，请更新为新密钥。",
      ja: "現在のシークレットは直ちに使えなくなります。次のリクエスト前にアプリを新しいシークレットへ更新してください。",
    },
  "Confirm high-impact change": { "zh-CN": "确认高影响变更", ja: "影響の大きい変更を確認" },
  "Client secret": { "zh-CN": "客户端密钥", ja: "クライアントシークレット" },
  "Copy this now — it is shown once and cannot be retrieved again.": {
    "zh-CN": "请立即复制——它只显示一次，之后无法找回。",
    ja: "今すぐコピーしてください。表示は1回限りで、後から取得できません。",
  },
  "Secret for {clientId}": { "zh-CN": "{clientId} 的密钥", ja: "{clientId} のシークレット" },
  Done: { "zh-CN": "完成", ja: "完了" },
  "User updated.": { "zh-CN": "用户已更新。", ja: "ユーザーを更新しました。" },
  "User created with an initial password.": {
    "zh-CN": "用户已创建并设置初始密码。",
    ja: "初期パスワード付きでユーザーを作成しました。",
  },
  "User created and invitation sent.": {
    "zh-CN": "用户已创建，邀请已发送。",
    ja: "ユーザーを作成し、招待を送信しました。",
  },
  "Password login method added.": {
    "zh-CN": "密码登录方式已添加。",
    ja: "パスワードログインを追加しました。",
  },
  "Password login method deleted.": {
    "zh-CN": "密码登录方式已删除。",
    ja: "パスワードログインを削除しました。",
  },
  "Passkey login method deleted.": {
    "zh-CN": "通行密钥登录方式已删除。",
    ja: "パスキーログインを削除しました。",
  },
  "Group access updated.": {
    "zh-CN": "群组访问权限已更新。",
    ja: "グループアクセスを更新しました。",
  },
  "Group created.": { "zh-CN": "群组已创建。", ja: "グループを作成しました。" },
  "Group updated.": { "zh-CN": "群组已更新。", ja: "グループを更新しました。" },
  "Group deleted.": { "zh-CN": "群组已删除。", ja: "グループを削除しました。" },
  "All of that user's sessions were revoked.": {
    "zh-CN": "该用户的所有会话已撤销。",
    ja: "そのユーザーの全セッションを取り消しました。",
  },
  "Client created.": { "zh-CN": "客户端已创建。", ja: "クライアントを作成しました。" },
  "Client updated.": { "zh-CN": "客户端已更新。", ja: "クライアントを更新しました。" },
  "Client deleted.": { "zh-CN": "客户端已删除。", ja: "クライアントを削除しました。" },
  "Client enabled.": { "zh-CN": "客户端已启用。", ja: "クライアントを有効にしました。" },
  "Client disabled.": { "zh-CN": "客户端已禁用。", ja: "クライアントを無効にしました。" },
  "Resource created.": { "zh-CN": "资源已创建。", ja: "リソースを作成しました。" },
  "Resource updated.": { "zh-CN": "资源已更新。", ja: "リソースを更新しました。" },
  "Device session revoked.": {
    "zh-CN": "设备会话已撤销。",
    ja: "デバイスセッションを取り消しました。",
  },
  "An account already uses that email address.": {
    "zh-CN": "已有账户使用该电子邮箱地址。",
    ja: "そのメールアドレスは別のアカウントで使用されています。",
  },
  "An account already uses that username.": {
    "zh-CN": "已有账户使用该用户名。",
    ja: "そのユーザー名は別のアカウントで使用されています。",
  },
  "Usernames may contain only English letters and numbers.": {
    "zh-CN": "用户名只能包含英文字母和数字。",
    ja: "ユーザー名には英字と数字のみ使用できます。",
  },
  "That password does not meet this user's policy.": {
    "zh-CN": "该密码不符合此用户的策略。",
    ja: "そのパスワードは、このユーザーのポリシーを満たしていません。",
  },
  "Add another password or passkey before deleting the last login method.": {
    "zh-CN": "删除最后一种登录方式前，请先添加另一个密码或通行密钥。",
    ja: "最後のログイン方法を削除する前に、別のパスワードまたはパスキーを追加してください。",
  },
  "Enable the user before generating a magic link.": {
    "zh-CN": "生成魔法链接前，请先启用该用户。",
    ja: "マジックリンクを生成する前にユーザーを有効にしてください。",
  },
  "A group with that name already exists.": {
    "zh-CN": "已存在同名群组。",
    ja: "同じ名前のグループがすでに存在します。",
  },
  "The admins group is protected.": {
    "zh-CN": "admins 群组受保护。",
    ja: "adminsグループは保護されています。",
  },
  "Choose only groups that currently exist.": {
    "zh-CN": "只能选择当前存在的群组。",
    ja: "現在存在するグループのみ選択してください。",
  },
  "Keep at least one active user in the admins group.": {
    "zh-CN": "admins 群组中必须至少保留一名活动用户。",
    ja: "adminsグループには有効なユーザーを1人以上残してください。",
  },
  "The account was not created. Check email delivery and try again.": {
    "zh-CN": "账户未创建。请检查电子邮件发送并重试。",
    ja: "アカウントは作成されませんでした。メール送信を確認してもう一度お試しください。",
  },
  "Please check the form and try again.": {
    "zh-CN": "请检查表单后重试。",
    ja: "フォームを確認して、もう一度お試しください。",
  },
  "Enter a valid email address of at most 254 characters.": {
    "zh-CN": "请输入不超过 254 个字符的有效电子邮箱地址。",
    ja: "254文字以内の有効なメールアドレスを入力してください。",
  },
  "Display names must contain at most 120 characters.": {
    "zh-CN": "显示名称最多可包含 120 个字符。",
    ja: "表示名は120文字以内で入力してください。",
  },
  "Initial passwords must contain 6–128 characters (12 for administrators).": {
    "zh-CN": "初始密码必须包含 6–128 个字符（管理员至少 12 个字符）。",
    ja: "初期パスワードは6〜128文字（管理者は12文字以上）で入力してください。",
  },
  "Select no more than {max} valid groups.": {
    "zh-CN": "最多选择 {max} 个有效群组。",
    ja: "有効なグループを{max}個以内で選択してください。",
  },
  "Check the form values.": { "zh-CN": "请检查表单值。", ja: "フォームの値を確認してください。" },
  "For security, the initial password was cleared; enter it again.": {
    "zh-CN": "出于安全考虑，初始密码已清除；请重新输入。",
    ja: "セキュリティのため初期パスワードを消去しました。もう一度入力してください。",
  },
  "That password does not meet the policy for the selected groups.": {
    "zh-CN": "该密码不符合所选群组的策略。",
    ja: "そのパスワードは選択したグループのポリシーを満たしていません。",
  },
  "One or more selected groups no longer exist. Review the group selection.": {
    "zh-CN": "一个或多个所选群组已不存在。请检查群组选择。",
    ja: "選択したグループの一部が存在しません。グループ選択を確認してください。",
  },
  "The group name did not match. Nothing was deleted.": {
    "zh-CN": "群组名称不匹配，未删除任何内容。",
    ja: "グループ名が一致しなかったため、何も削除されませんでした。",
  },
  "Redirect URIs must use HTTPS, loopback HTTP, or a reverse-domain native scheme, without credentials or fragments.":
    {
      "zh-CN": "重定向 URI 必须使用 HTTPS、回环 HTTP 或反向域名原生方案，且不得包含凭据或片段。",
      ja: "リダイレクトURIにはHTTPS、ループバックHTTP、または逆ドメイン形式のネイティブスキームを使用し、認証情報やフラグメントを含めないでください。",
    },
  "Post-logout redirect URIs must use HTTPS or loopback HTTP, without credentials or fragments.": {
    "zh-CN": "退出后的重定向 URI 必须使用 HTTPS 或回环 HTTP，且不得包含凭据或片段。",
    ja: "ログアウト後のリダイレクトURIにはHTTPSまたはループバックHTTPを使用し、認証情報やフラグメントを含めないでください。",
  },
  "Configuration error: {reason}.": {
    "zh-CN": "配置错误：{reason}。",
    ja: "設定エラー：{reason}。",
  },
  "That client ID is already registered.": {
    "zh-CN": "该客户端 ID 已注册。",
    ja: "そのクライアントIDはすでに登録されています。",
  },
  "The client ID did not match. No secret was changed.": {
    "zh-CN": "客户端 ID 不匹配，密钥未更改。",
    ja: "クライアントIDが一致しなかったため、シークレットは変更されませんでした。",
  },
  "The client ID did not match. Nothing was deleted.": {
    "zh-CN": "客户端 ID 不匹配，未删除任何内容。",
    ja: "クライアントIDが一致しなかったため、何も削除されませんでした。",
  },
  "client_id must be a URL-safe identifier of 1 to 128 characters": {
    "zh-CN": "client_id 必须是 1 到 128 个字符的 URL 安全标识符",
    ja: "client_idは1〜128文字のURL安全な識別子である必要があります",
  },
  "name must contain 1 to 120 characters": {
    "zh-CN": "名称必须包含 1 到 120 个字符",
    ja: "名前は1〜120文字である必要があります",
  },
  "configuration lists must not contain duplicates": {
    "zh-CN": "配置列表不得包含重复项",
    ja: "設定リストに重複を含めることはできません",
  },
  "allowed_scopes contains an unknown scope or is empty": {
    "zh-CN": "allowed_scopes 包含未知作用域或为空",
    ja: "allowed_scopesが空か、不明なスコープを含んでいます",
  },
  "allowed_grant_types contains an unsupported grant": {
    "zh-CN": "allowed_grant_types 包含不受支持的许可",
    ja: "allowed_grant_typesに未対応のグラントが含まれています",
  },
  "at least one protected resource is required": {
    "zh-CN": "至少需要一个受保护资源",
    ja: "保護対象リソースが1つ以上必要です",
  },
  "default_resource must be one of allowed_resources": {
    "zh-CN": "default_resource 必须是 allowed_resources 之一",
    ja: "default_resourceはallowed_resourcesのいずれかである必要があります",
  },
  "every allowed resource must be registered and enabled": {
    "zh-CN": "每个允许的资源都必须已注册并启用",
    ja: "許可するすべてのリソースは登録済みかつ有効である必要があります",
  },
  "one or more scopes are not offered by an allowed resource": {
    "zh-CN": "一个或多个作用域未由允许的资源提供",
    ja: "許可したリソースで提供されていないスコープがあります",
  },
  "public clients cannot use client_credentials": {
    "zh-CN": "公共客户端不能使用 client_credentials",
    ja: "パブリッククライアントはclient_credentialsを使用できません",
  },
  "offline_access requires the refresh_token grant": {
    "zh-CN": "offline_access 需要 refresh_token 许可",
    ja: "offline_accessにはrefresh_tokenグラントが必要です",
  },
  "application clients require authorization_code, redirects, and only optional refresh_token": {
    "zh-CN": "应用客户端需要 authorization_code 和重定向，并且只能额外使用可选的 refresh_token",
    ja: "アプリケーションクライアントにはauthorization_codeとリダイレクトが必要で、追加できるのは任意のrefresh_tokenだけです",
  },
  "device clients require device_code, no redirects, and only optional refresh_token": {
    "zh-CN": "设备客户端需要 device_code、不得设置重定向，并且只能额外使用可选的 refresh_token",
    ja: "デバイスクライアントにはdevice_codeが必要で、リダイレクトは不可、追加できるのは任意のrefresh_tokenだけです",
  },
  "service clients must be confidential, use only client_credentials, and exclude user scopes and redirects":
    {
      "zh-CN": "服务客户端必须为机密客户端，仅使用 client_credentials，并排除用户作用域和重定向",
      ja: "サービスクライアントはコンフィデンシャルで、client_credentialsのみを使用し、ユーザースコープとリダイレクトを含めない必要があります",
    },
} as const satisfies Readonly<Record<string, LocalizedMessage>>
