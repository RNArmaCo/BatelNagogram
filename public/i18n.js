// public/i18n.js
export const STRINGS = {
  fa: {
    pageTitle: "BatelNagogram — پیام‌رسان امن گروهی",
    defaultRoomTitle: "BatelNagogram",
    secureConn: "ارتباط امن",
    activeUsers: "کاربران فعال",
    loading: "در حال بارگذاری...",
    noActiveUsers: "کاربر فعالی نیست",
    emptyChat: "هنوز پیامی نیست. شروع کنید!",
    waitingSecure: "منتظر ارتباط امن...",
    msgPlaceholder: "پیام رمزنگاری‌شده بنویسید...",
    clickCopyLink: "کلیک برای کپی لینک",
    copyLink: "کپی لینک",
    switchRoom: "تغییر / ساخت اتاق",
    privateMessages: "پیام‌های خصوصی",
    roomSettings: "تنظیمات اتاق",
    logout: "خروج از حساب",
    cancelReply: "لغو پاسخ",
    sendFile: "ارسال فایل",
    send: "ارسال",
    authTitle: "ورود / ثبت‌نام در BatelNagogram",
    loginTab: "ورود با توکن",
    registerTab: "ثبت‌نام یکتا",
    usernameLabel: "نام کاربری یکتا",
    usernamePlaceholder: "مثلاً batel_user",
    tokenLabel: "توکن ورود",
    tokenPlaceholder: "bn_...",
    noPiiHint:
      "هیچ ایمیل، شماره یا اطلاعات هویتی ذخیره نمی‌شود. در ثبت‌نام فقط یک توکن اختصاصی دریافت می‌کنید.",
    saveTokenLabel: "توکن شما (فقط یک‌بار نمایش داده می‌شود):",
    loginBtn: "ورود",
    continueBtn: "ادامه",
    joinCreateTitle: "ورود / ایجاد اتاق",
    checkingRoom: "در حال بررسی اتاق...",
    roomCodeOrLinkLabel: "کد ۸ رقمی هگز یا لینک دعوت",
    roomNameLabel: "نام اتاق",
    roomNamePlaceholder: "مثلاً تیم طراحی",
    roomPasswordLabel: "رمز اتاق",
    optionalPlaceholder: "اختیاری",
    joinHintText:
      "با ورود هر کاربر جدید، دوره رمزنگاری اتاق به‌روز می‌شود تا کاربران جدید نتوانند پیام‌های قدیمی‌تر را رمزگشایی کنند.",
    randomRoomBtn: "کد تصادفی",
    roomIdLabel: "شناسه اتاق:",
    newRoomPassLabel: "رمز جدید اتاق",
    settingsHint:
      "اگر رمز را خالی ذخیره کنید، رمز اتاق حذف می‌شود. فقط سازنده اتاق می‌تواند این تنظیمات را تغییر دهد.",
    closeBtn: "بستن",
    saveSettingsBtn: "ذخیره تنظیمات",
    selectPeerHint: "یک کاربر را برای گفتگوی خصوصی رمزنگاری‌شده انتخاب کنید.",
    noDmPeers: "کاربر دیگری ثبت‌نام نکرده است.",
    dmPlaceholder: "پیام خصوصی رمزنگاری‌شده بنویسید...",
    typingOne: (u) => `${u} در حال نوشتن است...`,
    epochLabel: (ep) => `دوره #${ep}`,
    pastEpochLocked:
      "[پیام متعلق به دوره‌های پیشین است — امکان رمزگشایی برای اعضای جدید وجود ندارد]",
    decryptFailed: "[امکان رمزگشایی نیست — رمز یا کلید دوره را بررسی کنید]",
    deletedText: "[این پیام حذف شد]",
    editedLabel: "(ویرایش‌شده)",
    editBtn: "ویرایش",
    deleteBtn: "حذف",
    editPrompt: "متن جدید پیام:",
    linkCopied: "لینک دعوت کپی شد",
    settingsSaved: "تنظیمات اتاق ذخیره شد",
    replyPrefix: "پاسخ به",
    replyBtnTitle: "پاسخ",
    fileTooLarge: "حجم فایل از ۱۰۰ مگابایت بیشتر است",
    fileUploaded: (name) => `فایل «${name}» ارسال شد`,
    download: "دانلود",
    langToggle: "EN",
  },
  en: {
    pageTitle: "BatelNagogram — Secure Group Messenger",
    defaultRoomTitle: "BatelNagogram",
    secureConn: "Encrypted",
    activeUsers: "Active Users",
    loading: "Loading...",
    noActiveUsers: "No active users",
    emptyChat: "No messages yet. Start chatting!",
    waitingSecure: "Waiting for secure connection...",
    msgPlaceholder: "Write an encrypted message...",
    clickCopyLink: "Click to copy invite link",
    copyLink: "Copy Link",
    switchRoom: "Create / Join Room",
    privateMessages: "Private Messages",
    roomSettings: "Room Settings",
    logout: "Logout",
    cancelReply: "Cancel reply",
    sendFile: "Attach file",
    send: "Send",
    authTitle: "BatelNagogram — Login / Register",
    loginTab: "Login with Token",
    registerTab: "Register Username",
    usernameLabel: "Unique Username",
    usernamePlaceholder: "e.g. batel_user",
    tokenLabel: "Login Token",
    tokenPlaceholder: "bn_...",
    noPiiHint:
      "No email, phone, or personal data is stored. Registration issues a one-time login token.",
    saveTokenLabel: "Save this token (shown only once):",
    loginBtn: "Login",
    continueBtn: "Continue",
    joinCreateTitle: "Join or Create Room",
    checkingRoom: "Checking room...",
    roomCodeOrLinkLabel: "8-Hex Room Code or Invite Link",
    roomNameLabel: "Room Name",
    roomNamePlaceholder: "e.g. Design Team",
    roomPasswordLabel: "Room Password",
    optionalPlaceholder: "Optional",
    joinHintText:
      "Each new join rotates the room encryption epoch so newcomers cannot decrypt older messages.",
    randomRoomBtn: "Random Code",
    roomIdLabel: "Room ID:",
    newRoomPassLabel: "New Room Password",
    settingsHint:
      "Saving an empty password removes the room lock. Only the room creator can edit settings.",
    closeBtn: "Close",
    saveSettingsBtn: "Save Settings",
    selectPeerHint: "Select a user to start an E2EE private conversation.",
    noDmPeers: "No other registered users yet.",
    dmPlaceholder: "Write an encrypted private message...",
    typingOne: (u) => `${u} is typing...`,
    epochLabel: (ep) => `Epoch #${ep}`,
    pastEpochLocked:
      "[Message from an earlier epoch — unavailable to newer joiners]",
    decryptFailed: "[Unable to decrypt — check room password or epoch key]",
    deletedText: "[Message deleted]",
    editedLabel: "(edited)",
    editBtn: "Edit",
    deleteBtn: "Delete",
    editPrompt: "Enter updated message text:",
    linkCopied: "Invite link copied",
    settingsSaved: "Room settings saved",
    replyPrefix: "Replying to",
    replyBtnTitle: "Reply",
    fileTooLarge: "File exceeds the 100MB limit",
    fileUploaded: (name) => `Uploaded "${name}"`,
    download: "Download",
    langToggle: "FA",
  },
};

export function getLang() {
  const saved = localStorage.getItem("bn_lang");
  if (saved === "fa" || saved === "en") return saved;
  return navigator.language?.toLowerCase().startsWith("fa") ? "fa" : "en";
}

export function applyLang(lang) {
  localStorage.setItem("bn_lang", lang);
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";

  const dict = STRINGS[lang];
  document.title = dict.pageTitle;

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key && typeof dict[key] === "string") el.textContent = dict[key];
  });

  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key && typeof dict[key] === "string")
      el.setAttribute("placeholder", dict[key]);
  });

  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    const key = el.getAttribute("data-i18n-title");
    if (key && typeof dict[key] === "string")
      el.setAttribute("title", dict[key]);
  });

  const toggle = document.getElementById("langSwitchBtn");
  if (toggle) toggle.textContent = dict.langToggle;
}
