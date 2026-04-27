// Server-side email/SMS translations. Kept deliberately small and key-based so email.js can
// look up a phrase by (lang, key) and render templates without branching per-language.
const SUPPORTED = ['en', 'fr', 'hi'];

const translations = {
  en: {
    'email.login_subject': 'Your CertaDocs login verification code',
    'email.login_body': 'Your login verification code is:',
    'email.login_expire': "This code expires in 10 minutes. If you didn't request this, ignore this email.",
    'email.signer_subject': 'Your CertaDocs verification code',
    'email.signer_hi': 'Hi {name},',
    'email.signer_body': 'Enter this code to verify your identity before signing:',
    'email.signer_expire': 'This code expires in 10 minutes.',
    'email.request_subject': '{sender} requested your signature: {title}',
    'email.request_body': '<strong>{sender}</strong> has requested your signature on:',
    'email.request_button': 'Review & Sign',
    'email.request_note': 'You will be asked to verify your email before signing.',
    'email.reminder_subject': 'Reminder: Please sign "{title}"',
    'email.reminder_body': 'This is a friendly reminder that <strong>{sender}</strong> is still waiting for your signature on:',
    'email.expiry_note': 'Note: This request expires on {date}.',
    'email.complete_subject': 'Completed: All signatures collected for "{title}"',
    'email.complete_body': 'All signatures have been collected for "{title}".',
    'email.decline_subject': 'Declined: {signer} declined to sign "{title}"',
    'email.decline_body': '<strong>{signer}</strong> has declined to sign <strong>"{title}"</strong>.',
    'email.decline_reason': 'Reason:',
    'email.expired_subject': 'Expired: "{title}" is no longer available for signing',
    'email.expired_body': 'The signing request for "<strong>{title}</strong>" has expired and was automatically cancelled.',
    'email.invite_subject': '{inviter} invited you to join {org} on CertaDocs',
    'email.invite_body': '<strong>{inviter}</strong> has invited you to join the <strong>{org}</strong> workspace as a <strong>{role}</strong>.',
    'email.invite_button': 'Accept Invitation',
    'email.invite_note': 'This invitation expires in 7 days. If you don\'t recognise the sender, you can safely ignore this email.',
    'sms.signer_request': 'You have a document to sign from {sender}: {url}',
    'sms.reminder': 'Reminder: please sign "{title}" — {url}',
    'sms.otp': 'Your CertaDocs code: {code}',
  },
  fr: {
    'email.login_subject': 'Votre code de vérification CertaDocs',
    'email.login_body': 'Votre code de vérification de connexion est :',
    'email.login_expire': "Ce code expire dans 10 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez ce courriel.",
    'email.signer_subject': 'Votre code de vérification CertaDocs',
    'email.signer_hi': 'Bonjour {name},',
    'email.signer_body': 'Entrez ce code pour vérifier votre identité avant de signer :',
    'email.signer_expire': 'Ce code expire dans 10 minutes.',
    'email.request_subject': '{sender} demande votre signature : {title}',
    'email.request_body': '<strong>{sender}</strong> a demandé votre signature sur :',
    'email.request_button': 'Réviser et signer',
    'email.request_note': 'On vous demandera de vérifier votre courriel avant de signer.',
    'email.reminder_subject': 'Rappel : Veuillez signer « {title} »',
    'email.reminder_body': 'Rappel amical : <strong>{sender}</strong> attend toujours votre signature sur :',
    'email.expiry_note': 'Remarque : Cette demande expire le {date}.',
    'email.complete_subject': 'Terminé : Toutes les signatures collectées pour « {title} »',
    'email.complete_body': 'Toutes les signatures ont été collectées pour « {title} ».',
    'email.decline_subject': 'Refusé : {signer} a refusé de signer « {title} »',
    'email.decline_body': '<strong>{signer}</strong> a refusé de signer <strong>« {title} »</strong>.',
    'email.decline_reason': 'Raison :',
    'email.expired_subject': 'Expiré : « {title} » n\'est plus disponible à la signature',
    'email.expired_body': 'La demande de signature pour « <strong>{title}</strong> » a expiré et a été annulée automatiquement.',
    'email.invite_subject': '{inviter} vous invite à rejoindre {org} sur CertaDocs',
    'email.invite_body': '<strong>{inviter}</strong> vous invite à rejoindre l\'espace de travail <strong>{org}</strong> en tant que <strong>{role}</strong>.',
    'email.invite_button': 'Accepter l\'invitation',
    'email.invite_note': 'Cette invitation expire dans 7 jours. Si vous ne reconnaissez pas l\'expéditeur, ignorez ce courriel.',
    'sms.signer_request': 'Document à signer de {sender} : {url}',
    'sms.reminder': 'Rappel : signer « {title} » — {url}',
    'sms.otp': 'Votre code CertaDocs : {code}',
  },
  hi: {
    'email.login_subject': 'आपका CertaDocs लॉगिन सत्यापन कोड',
    'email.login_body': 'आपका लॉगिन सत्यापन कोड:',
    'email.login_expire': 'यह कोड 10 मिनट में समाप्त हो जाएगा। यदि आपने अनुरोध नहीं किया है, तो इस ईमेल को अनदेखा करें।',
    'email.signer_subject': 'आपका CertaDocs सत्यापन कोड',
    'email.signer_hi': 'नमस्ते {name},',
    'email.signer_body': 'हस्ताक्षर से पहले अपनी पहचान सत्यापित करने के लिए यह कोड दर्ज करें:',
    'email.signer_expire': 'यह कोड 10 मिनट में समाप्त हो जाएगा।',
    'email.request_subject': '{sender} ने आपके हस्ताक्षर का अनुरोध किया: {title}',
    'email.request_body': '<strong>{sender}</strong> ने आपके हस्ताक्षर का अनुरोध किया है:',
    'email.request_button': 'समीक्षा करें और हस्ताक्षर करें',
    'email.request_note': 'हस्ताक्षर से पहले आपको अपना ईमेल सत्यापित करना होगा।',
    'email.reminder_subject': 'अनुस्मारक: कृपया "{title}" पर हस्ताक्षर करें',
    'email.reminder_body': 'यह एक मित्रवत अनुस्मारक है — <strong>{sender}</strong> अभी भी आपके हस्ताक्षर की प्रतीक्षा कर रहे हैं:',
    'email.expiry_note': 'ध्यान दें: यह अनुरोध {date} को समाप्त होता है।',
    'email.complete_subject': 'पूर्ण: "{title}" के लिए सभी हस्ताक्षर एकत्र किए गए',
    'email.complete_body': '"{title}" के लिए सभी हस्ताक्षर एकत्र कर लिए गए हैं।',
    'email.decline_subject': 'अस्वीकृत: {signer} ने "{title}" पर हस्ताक्षर करने से मना कर दिया',
    'email.decline_body': '<strong>{signer}</strong> ने <strong>"{title}"</strong> पर हस्ताक्षर करने से मना कर दिया है।',
    'email.decline_reason': 'कारण:',
    'email.expired_subject': 'समाप्त: "{title}" अब हस्ताक्षर के लिए उपलब्ध नहीं है',
    'email.expired_body': '"<strong>{title}</strong>" का हस्ताक्षर अनुरोध समाप्त हो गया और स्वचालित रूप से रद्द कर दिया गया।',
    'email.invite_subject': '{inviter} ने आपको CertaDocs पर {org} में शामिल होने के लिए आमंत्रित किया',
    'email.invite_body': '<strong>{inviter}</strong> ने आपको <strong>{org}</strong> कार्यक्षेत्र में <strong>{role}</strong> के रूप में शामिल होने के लिए आमंत्रित किया है।',
    'email.invite_button': 'निमंत्रण स्वीकार करें',
    'email.invite_note': 'यह निमंत्रण 7 दिनों में समाप्त हो जाता है।',
    'sms.signer_request': '{sender} से एक दस्तावेज़ हस्ताक्षर के लिए: {url}',
    'sms.reminder': 'अनुस्मारक: "{title}" पर हस्ताक्षर करें — {url}',
    'sms.otp': 'आपका CertaDocs कोड: {code}',
  },
};

function normalize(lang) {
  if (!lang) return 'en';
  const l = String(lang).toLowerCase();
  return SUPPORTED.includes(l) ? l : 'en';
}

function t(lang, key, vars) {
  const L = normalize(lang);
  let s = (translations[L] && translations[L][key]) || translations.en[key] || key;
  if (vars) for (const k in vars) s = String(s).split('{' + k + '}').join(String(vars[k] == null ? '' : vars[k]));
  return s;
}

module.exports = { t, SUPPORTED, normalize };
