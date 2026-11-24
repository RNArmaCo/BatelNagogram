// src/i18n.ts
export type Lang = "en" | "fa";

const API_TEXT = {
  en: {
    unauthorized: "Please log in with your username and token.",
    usernameTaken: "That username is already taken.",
    invalidLogin: "Invalid username or login token.",
    invalidRoom: "Room code must be 8 hex characters.",
    roomNotFound: "Room not found.",
    wrongPassword: "Incorrect room password.",
    onlyCreator: "Only the room creator can change room settings.",
    missingParams: "Missing required fields.",
    recipientNotFound: "Recipient user not found.",
    messageNotFound: "Message not found.",
    forbiddenEdit: "You can only edit or delete your own messages.",
    fileTooLarge: "File exceeds the 100MB limit.",
    chunkTooLarge: "File chunk exceeds the 10MB limit.",
    fileNotFound: "File not found.",
    joined: (u: string) => `${u} joined the room`,
    left: (u: string) => `${u} left the room`,
    epochRotated: (epoch: number) =>
      `Room key rotated to epoch #${epoch} for forward secrecy`,
    serverError: "Server error",
  },
  fa: {
    unauthorized: "لطفاً با نام کاربری و توکن خود وارد شوید.",
    usernameTaken: "این نام کاربری قبلاً ثبت شده است.",
    invalidLogin: "نام کاربری یا توکن ورود نامعتبر است.",
    invalidRoom: "کد اتاق باید ۸ کاراکتر هگزادسیمال باشد.",
    roomNotFound: "اتاق پیدا نشد.",
    wrongPassword: "رمز عبور اتاق اشتباه است.",
    onlyCreator: "فقط سازنده اتاق می‌تواند تنظیمات را تغییر دهد.",
    missingParams: "اطلاعات الزامی کامل نیست.",
    recipientNotFound: "کاربر مخاطب پیدا نشد.",
    messageNotFound: "پیام پیدا نشد.",
    forbiddenEdit: "فقط می‌توانید پیام‌های خود را ویرایش یا حذف کنید.",
    fileTooLarge: "حجم فایل از محدودیت ۱۰۰ مگابایت بیشتر است.",
    chunkTooLarge: "حجم بخش فایل از محدودیت ۱۰ مگابایت بیشتر است.",
    fileNotFound: "فایل پیدا نشد.",
    joined: (u: string) => `${u} وارد اتاق شد`,
    left: (u: string) => `${u} از اتاق خارج شد`,
    epochRotated: (epoch: number) =>
      `کلید اتاق به دوره #${epoch} برای امنیت رو به جلو به‌روز شد`,
    serverError: "خطای سرور",
  },
} as const;

export function resolveLang(req: Request, bodyLang?: unknown): Lang {
  const q = new URL(req.url).searchParams.get("lang");
  if (q === "fa" || q === "en") return q;
  if (bodyLang === "fa" || bodyLang === "en") return bodyLang;
  const accept = req.headers.get("accept-language") ?? "";
  return accept.toLowerCase().includes("fa") ? "fa" : "en";
}

export function apiMsg(lang: Lang) {
  return API_TEXT[lang];
}
