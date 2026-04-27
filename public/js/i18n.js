// CertaDocs i18n — lightweight client-side translations (EN, FR, HI)
// Markets: Canada (EN/FR — Quebec Law 25), US (EN), India (EN/HI), Australia (EN), Europe (EN; more on demand).
(function () {
  const STORAGE_KEY = 'certadocs_lang';

  const dict = {
    en: {
      // Common
      'app.title': 'CertaDocs',
      'common.dashboard': 'Dashboard',
      'common.templates': 'Templates',
      'common.verify': 'Verify',
      'common.logout': 'Logout',
      'common.cancel': 'Cancel',
      'common.delete': 'Delete',
      'common.save': 'Save',
      'common.loading': 'Loading...',
      'common.send': 'Send',
      'common.back': 'Back',
      'common.download': 'Download',
      'common.email': 'Email',
      'common.name': 'Name',
      'common.copied': 'Copied!',
      'common.required': 'Required',
      'common.optional': 'optional',
      'common.language': 'Language',
      'common.continue': 'Continue',
      'common.close': 'Close',
      'common.yes': 'Yes',
      'common.no': 'No',

      // Login
      'login.title': 'Sign in to CertaDocs',
      'login.subtitle': 'Email-based passwordless login.',
      'login.email_placeholder': 'you@example.com',
      'login.send_code': 'Send Verification Code',
      'login.code_sent': 'A 6-digit code was sent. Enter it below.',
      'login.code_placeholder': '------',
      'login.verify': 'Verify',
      'login.name_placeholder': 'Your full name (first time only)',
      'login.invalid_code': 'Invalid or expired code.',

      // Dashboard
      'dash.your_documents': 'Your Documents',
      'dash.send_for_others': 'Send for Others to Sign',
      'dash.sign_myself': 'Sign Myself',
      'dash.no_docs': 'No documents yet',
      'dash.no_docs_hint': 'Send for Others to Sign — upload a PDF and add signers. Sign Myself — sign a PDF instantly.',
      'dash.signed': 'signed',
      'dash.status_draft': 'draft',
      'dash.status_pending': 'pending',
      'dash.status_completed': 'completed',
      'dash.status_cancelled': 'cancelled',
      'dash.signers': 'Signers',
      'dash.cancel_request': 'Cancel Request',
      'dash.cancel_confirm': 'Cancel this signing request? Signers will no longer be able to sign. This cannot be undone.',
      'dash.resend': 'Resend',
      'dash.download_signed': 'Download Signed PDF',
      'dash.email_not_configured': 'Email not configured. Share the signing links above manually.',

      // Send
      'send.title': 'New Signing Request',
      'send.upload_doc': '1. Upload Document',
      'send.upload_hint': 'Drop your PDF here or click to browse',
      'send.doc_details': '2. Document Details',
      'send.title_label': 'Title',
      'send.title_ph': 'e.g. Q4 Contract Agreement',
      'send.message_label': 'Message to signers (optional)',
      'send.message_ph': 'Please review and sign this document by Friday.',
      'send.add_signers': '3. Add Signers',
      'send.mode_seq_title': 'Sequential',
      'send.mode_seq_desc': 'Each signer is notified after the previous one signs.',
      'send.mode_par_title': 'Parallel',
      'send.mode_par_desc': 'All signers are notified at once and can sign in any order.',
      'send.signer_hint': 'Drag the handle to reorder. Roles: Sign (signs), Approve (approves & signs), CC (notified at completion only), Witness (witnesses the signer).',
      'send.add_another': '+ Add another signer',
      'send.place_fields': '4. Place Fields (optional)',
      'send.fields_help': 'Click a field type, then click on the PDF where you want it. Click a placed field to assign it to a signer or change its label.',
      'send.save_template': '5. Save as Template (optional)',
      'send.save_template_label': 'Save these settings as a template for future use',
      'send.template_name_ph': 'Template name (e.g. Standard NDA)',
      'send.send_btn': 'Send for Signing',
      'send.start_template': 'Start from Template',
      'send.template_loaded': '✓ Loaded from template. Edit anything before sending.',
      'send.role_sign': 'Sign',
      'send.role_approve': 'Approve',
      'send.role_cc': 'CC',
      'send.role_witness': 'Witness',
      'send.err_min_signer': 'Add at least one signer with name and email.',
      'send.err_no_pdf': 'Please upload a PDF.',
      'send.err_min_signing_role': 'At least one signer must have role Sign or Approve.',
      'send.sending': 'Sending...',
      'send.detect_fields': 'Auto-detect Fields',
      'send.detect_running': 'Scanning PDF...',
      'send.detect_done': '{n} field(s) detected and placed.',
      'send.preferred_lang': 'Preferred language',

      // Sign
      'sign.title': 'Sign Document',
      'sign.signing_as': 'Signing as',
      'sign.verify_id': 'Verify Your Identity',
      'sign.code_will_be_sent': 'A verification code will be sent to your email.',
      'sign.send_code': 'Send Verification Code',
      'sign.resend_code': 'Resend Code',
      'sign.enter_code_to': 'Enter the 6-digit code sent to',
      'sign.review_doc': 'Review Document',
      'sign.draw_signature': 'Draw Your Signature',
      'sign.clear': 'Clear',
      'sign.draw_above': 'Draw your signature above',
      'sign.sign_btn': 'Sign Document',
      'sign.legal_disclaimer': 'By signing, you agree this is your legal signature.',
      'sign.success': 'Document Signed!',
      'sign.success_msg': 'Your signature has been recorded. The document owner will be notified.',
      'sign.success_msg_complete': 'All signatures collected! Everyone will receive a copy of the signed document.',
      'sign.err_draw': 'Please draw your signature above.',
      'sign.submitting': 'Submitting...',
      'sign.fields_to_fill': 'Fields to fill',
      'sign.required_completed': 'required completed.',
      'sign.consent_title': 'Electronic-Signature Consent',
      'sign.consent_esign': 'I consent to use electronic records and signatures for this transaction. I understand my electronic signature is legally binding under applicable law (ESIGN/UETA in the US, PIPEDA in Canada, IT Act 2000 in India, ETA 1999 in Australia, eIDAS in the EU).',
      'sign.consent_privacy': 'I acknowledge that my IP address, browser, timestamp, email, and (if captured) phone/ID document will be stored as part of the audit trail for this signing.',
      'sign.consent_accept': 'I agree and consent',
      'sign.consent_decline': 'I do not agree',
      'sign.aadhaar_option': 'Sign with Aadhaar (India)',
      'sign.aadhaar_desc': 'Use your 12-digit Aadhaar number. You will receive an OTP on your Aadhaar-linked mobile.',
      'sign.aadhaar_enter': 'Enter your 12-digit Aadhaar number',
      'sign.aadhaar_otp': 'Enter the OTP sent to your Aadhaar-linked mobile',
      'sign.witness_title': 'Witness Signature',
      'sign.witness_confirm': 'I witnessed {name} sign this document in my presence.',

      // Templates
      'tpl.title': 'Templates',
      'tpl.saved': 'Saved Templates',
      'tpl.create': '+ Create Document (and save as template)',
      'tpl.no_templates': 'No templates yet',
      'tpl.no_templates_hint': 'Create a signing request and tick "Save as template" to add one.',
      'tpl.use': 'Use',
      'tpl.delete_confirm': 'Delete template "{name}"? This cannot be undone.',
      'tpl.signers_n': 'signer(s)',
      'tpl.pdf_included': 'PDF included',
      'tpl.no_pdf': 'No PDF',
    },
    fr: {
      'app.title': 'CertaDocs',
      'common.dashboard': 'Tableau de bord',
      'common.templates': 'Modèles',
      'common.verify': 'Vérifier',
      'common.logout': 'Déconnexion',
      'common.cancel': 'Annuler',
      'common.delete': 'Supprimer',
      'common.save': 'Enregistrer',
      'common.loading': 'Chargement...',
      'common.send': 'Envoyer',
      'common.back': 'Retour',
      'common.download': 'Télécharger',
      'common.email': 'Courriel',
      'common.name': 'Nom',
      'common.copied': 'Copié !',
      'common.required': 'Obligatoire',
      'common.optional': 'facultatif',
      'common.language': 'Langue',
      'common.continue': 'Continuer',
      'common.close': 'Fermer',
      'common.yes': 'Oui',
      'common.no': 'Non',

      'login.title': 'Connexion à CertaDocs',
      'login.subtitle': 'Connexion sans mot de passe par courriel.',
      'login.email_placeholder': 'vous@exemple.com',
      'login.send_code': 'Envoyer le code',
      'login.code_sent': 'Un code à 6 chiffres a été envoyé. Saisissez-le ci-dessous.',
      'login.code_placeholder': '------',
      'login.verify': 'Vérifier',
      'login.name_placeholder': 'Votre nom complet (première fois seulement)',
      'login.invalid_code': 'Code invalide ou expiré.',

      'dash.your_documents': 'Vos documents',
      'dash.send_for_others': 'Envoyer pour signature',
      'dash.sign_myself': 'Signer moi-même',
      'dash.no_docs': 'Aucun document',
      'dash.no_docs_hint': 'Envoyer pour signature — téléversez un PDF et ajoutez des signataires. Signer moi-même — signez un PDF instantanément.',
      'dash.signed': 'signé(s)',
      'dash.status_draft': 'brouillon',
      'dash.status_pending': 'en attente',
      'dash.status_completed': 'terminé',
      'dash.status_cancelled': 'annulé',
      'dash.signers': 'Signataires',
      'dash.cancel_request': 'Annuler la demande',
      'dash.cancel_confirm': 'Annuler cette demande de signature ? Les signataires ne pourront plus signer. Cette action est irréversible.',
      'dash.resend': 'Renvoyer',
      'dash.download_signed': 'Télécharger le PDF signé',
      'dash.email_not_configured': 'Courriel non configuré. Partagez les liens de signature manuellement.',

      'send.title': 'Nouvelle demande de signature',
      'send.upload_doc': '1. Téléverser le document',
      'send.upload_hint': 'Déposez votre PDF ici ou cliquez pour parcourir',
      'send.doc_details': '2. Détails du document',
      'send.title_label': 'Titre',
      'send.title_ph': 'ex. Contrat T4',
      'send.message_label': 'Message aux signataires (facultatif)',
      'send.message_ph': 'Veuillez réviser et signer ce document avant vendredi.',
      'send.add_signers': '3. Ajouter des signataires',
      'send.mode_seq_title': 'Séquentiel',
      'send.mode_seq_desc': 'Chaque signataire est notifié après que le précédent ait signé.',
      'send.mode_par_title': 'Parallèle',
      'send.mode_par_desc': 'Tous les signataires sont notifiés en même temps et peuvent signer dans n\'importe quel ordre.',
      'send.signer_hint': 'Glissez la poignée pour réorganiser. Rôles : Signer, Approuver, CC (notifié à la fin seulement), Témoin.',
      'send.add_another': '+ Ajouter un autre signataire',
      'send.place_fields': '4. Placer les champs (facultatif)',
      'send.fields_help': 'Cliquez sur un type de champ, puis cliquez sur le PDF à l\'endroit voulu. Cliquez sur un champ placé pour l\'attribuer à un signataire.',
      'send.save_template': '5. Enregistrer comme modèle (facultatif)',
      'send.save_template_label': 'Enregistrer ces paramètres comme modèle réutilisable',
      'send.template_name_ph': 'Nom du modèle (ex. NDA standard)',
      'send.send_btn': 'Envoyer pour signature',
      'send.start_template': 'Commencer à partir d\'un modèle',
      'send.template_loaded': '✓ Modèle chargé. Modifiez avant l\'envoi.',
      'send.role_sign': 'Signer',
      'send.role_approve': 'Approuver',
      'send.role_cc': 'CC',
      'send.role_witness': 'Témoin',
      'send.err_min_signer': 'Ajoutez au moins un signataire avec nom et courriel.',
      'send.err_no_pdf': 'Veuillez téléverser un PDF.',
      'send.err_min_signing_role': 'Au moins un signataire doit avoir le rôle Signer ou Approuver.',
      'send.sending': 'Envoi en cours...',
      'send.detect_fields': 'Détecter automatiquement',
      'send.detect_running': 'Analyse du PDF...',
      'send.detect_done': '{n} champ(s) détecté(s) et placé(s).',
      'send.preferred_lang': 'Langue préférée',

      'sign.title': 'Signer le document',
      'sign.signing_as': 'Signature en tant que',
      'sign.verify_id': 'Vérifiez votre identité',
      'sign.code_will_be_sent': 'Un code de vérification sera envoyé à votre courriel.',
      'sign.send_code': 'Envoyer le code',
      'sign.resend_code': 'Renvoyer le code',
      'sign.enter_code_to': 'Entrez le code à 6 chiffres envoyé à',
      'sign.review_doc': 'Réviser le document',
      'sign.draw_signature': 'Dessinez votre signature',
      'sign.clear': 'Effacer',
      'sign.draw_above': 'Dessinez votre signature ci-dessus',
      'sign.sign_btn': 'Signer le document',
      'sign.legal_disclaimer': 'En signant, vous reconnaissez qu\'il s\'agit de votre signature légale.',
      'sign.success': 'Document signé !',
      'sign.success_msg': 'Votre signature a été enregistrée. Le propriétaire du document sera notifié.',
      'sign.success_msg_complete': 'Toutes les signatures ont été collectées ! Tous recevront une copie du document signé.',
      'sign.err_draw': 'Veuillez dessiner votre signature ci-dessus.',
      'sign.submitting': 'Soumission...',
      'sign.fields_to_fill': 'Champs à remplir',
      'sign.required_completed': 'champs obligatoires complétés.',
      'sign.consent_title': 'Consentement à la signature électronique',
      'sign.consent_esign': 'Je consens à utiliser des documents et signatures électroniques pour cette transaction. Je comprends que ma signature électronique est juridiquement contraignante en vertu des lois applicables (LPRPDE au Canada, Loi 25 au Québec, eIDAS dans l\'UE).',
      'sign.consent_privacy': 'Je reconnais que mon adresse IP, mon navigateur, l\'horodatage, mon courriel et (si fournis) mon téléphone et documents d\'identité seront conservés dans la piste d\'audit.',
      'sign.consent_accept': 'J\'accepte et je consens',
      'sign.consent_decline': 'Je n\'accepte pas',
      'sign.aadhaar_option': 'Signer avec Aadhaar (Inde)',
      'sign.aadhaar_desc': 'Utilisez votre numéro Aadhaar à 12 chiffres.',
      'sign.aadhaar_enter': 'Entrez votre numéro Aadhaar à 12 chiffres',
      'sign.aadhaar_otp': 'Entrez le OTP reçu sur votre mobile lié à Aadhaar',
      'sign.witness_title': 'Signature du témoin',
      'sign.witness_confirm': 'J\'atteste que {name} a signé ce document en ma présence.',

      'tpl.title': 'Modèles',
      'tpl.saved': 'Modèles enregistrés',
      'tpl.create': '+ Créer un document (et enregistrer comme modèle)',
      'tpl.no_templates': 'Aucun modèle',
      'tpl.no_templates_hint': 'Créez une demande de signature et cochez « Enregistrer comme modèle ».',
      'tpl.use': 'Utiliser',
      'tpl.delete_confirm': 'Supprimer le modèle « {name} » ? Cette action est irréversible.',
      'tpl.signers_n': 'signataire(s)',
      'tpl.pdf_included': 'PDF inclus',
      'tpl.no_pdf': 'Sans PDF',
    },
    hi: {
      'app.title': 'CertaDocs',
      'common.dashboard': 'डैशबोर्ड',
      'common.templates': 'टेम्पलेट',
      'common.verify': 'सत्यापित करें',
      'common.logout': 'लॉगआउट',
      'common.cancel': 'रद्द करें',
      'common.delete': 'हटाएं',
      'common.save': 'सहेजें',
      'common.loading': 'लोड हो रहा है...',
      'common.send': 'भेजें',
      'common.back': 'वापस',
      'common.download': 'डाउनलोड',
      'common.email': 'ईमेल',
      'common.name': 'नाम',
      'common.copied': 'कॉपी किया गया!',
      'common.required': 'आवश्यक',
      'common.optional': 'वैकल्पिक',
      'common.language': 'भाषा',
      'common.continue': 'जारी रखें',
      'common.close': 'बंद करें',
      'common.yes': 'हाँ',
      'common.no': 'नहीं',

      'login.title': 'CertaDocs में साइन इन करें',
      'login.subtitle': 'ईमेल-आधारित पासवर्ड-रहित लॉगिन।',
      'login.email_placeholder': 'aap@example.com',
      'login.send_code': 'सत्यापन कोड भेजें',
      'login.code_sent': 'एक 6-अंकीय कोड भेजा गया है। कृपया नीचे दर्ज करें।',
      'login.code_placeholder': '------',
      'login.verify': 'सत्यापित करें',
      'login.name_placeholder': 'आपका पूरा नाम (केवल पहली बार)',
      'login.invalid_code': 'अमान्य या समाप्त कोड।',

      'dash.your_documents': 'आपके दस्तावेज़',
      'dash.send_for_others': 'दूसरों को हस्ताक्षर के लिए भेजें',
      'dash.sign_myself': 'स्वयं हस्ताक्षर करें',
      'dash.no_docs': 'अभी कोई दस्तावेज़ नहीं',
      'dash.no_docs_hint': 'दूसरों को हस्ताक्षर के लिए भेजें — PDF अपलोड करें। स्वयं हस्ताक्षर करें — तुरंत PDF पर हस्ताक्षर करें।',
      'dash.signed': 'हस्ताक्षरित',
      'dash.status_draft': 'मसौदा',
      'dash.status_pending': 'लंबित',
      'dash.status_completed': 'पूर्ण',
      'dash.status_cancelled': 'रद्द',
      'dash.signers': 'हस्ताक्षरकर्ता',
      'dash.cancel_request': 'अनुरोध रद्द करें',
      'dash.cancel_confirm': 'इस हस्ताक्षर अनुरोध को रद्द करें? हस्ताक्षरकर्ता अब हस्ताक्षर नहीं कर पाएंगे। यह पूर्ववत नहीं किया जा सकता।',
      'dash.resend': 'पुनः भेजें',
      'dash.download_signed': 'हस्ताक्षरित PDF डाउनलोड करें',
      'dash.email_not_configured': 'ईमेल कॉन्फ़िगर नहीं है। कृपया लिंक मैन्युअल रूप से साझा करें।',

      'send.title': 'नया हस्ताक्षर अनुरोध',
      'send.upload_doc': '1. दस्तावेज़ अपलोड करें',
      'send.upload_hint': 'अपना PDF यहाँ छोड़ें या ब्राउज़ करने के लिए क्लिक करें',
      'send.doc_details': '2. दस्तावेज़ विवरण',
      'send.title_label': 'शीर्षक',
      'send.title_ph': 'उदा. Q4 अनुबंध',
      'send.message_label': 'हस्ताक्षरकर्ताओं को संदेश (वैकल्पिक)',
      'send.message_ph': 'कृपया शुक्रवार तक इस दस्तावेज़ की समीक्षा करें और हस्ताक्षर करें।',
      'send.add_signers': '3. हस्ताक्षरकर्ता जोड़ें',
      'send.mode_seq_title': 'क्रमिक',
      'send.mode_seq_desc': 'पिछले हस्ताक्षर के बाद प्रत्येक हस्ताक्षरकर्ता को सूचित किया जाता है।',
      'send.mode_par_title': 'समानांतर',
      'send.mode_par_desc': 'सभी हस्ताक्षरकर्ताओं को एक साथ सूचित किया जाता है।',
      'send.signer_hint': 'पुनः क्रमित करने के लिए हैंडल खींचें। भूमिकाएँ: हस्ताक्षर, अनुमोदन, CC, साक्षी।',
      'send.add_another': '+ एक और हस्ताक्षरकर्ता जोड़ें',
      'send.place_fields': '4. फ़ील्ड रखें (वैकल्पिक)',
      'send.fields_help': 'एक फ़ील्ड प्रकार पर क्लिक करें, फिर PDF पर जहाँ चाहें क्लिक करें।',
      'send.save_template': '5. टेम्पलेट के रूप में सहेजें (वैकल्पिक)',
      'send.save_template_label': 'इन सेटिंग्स को भविष्य के लिए टेम्पलेट के रूप में सहेजें',
      'send.template_name_ph': 'टेम्पलेट नाम (उदा. मानक NDA)',
      'send.send_btn': 'हस्ताक्षर के लिए भेजें',
      'send.start_template': 'टेम्पलेट से शुरू करें',
      'send.template_loaded': '✓ टेम्पलेट लोड किया गया। भेजने से पहले संपादित करें।',
      'send.role_sign': 'हस्ताक्षर',
      'send.role_approve': 'अनुमोदन',
      'send.role_cc': 'CC',
      'send.role_witness': 'साक्षी',
      'send.err_min_signer': 'नाम और ईमेल सहित कम से कम एक हस्ताक्षरकर्ता जोड़ें।',
      'send.err_no_pdf': 'कृपया एक PDF अपलोड करें।',
      'send.err_min_signing_role': 'कम से कम एक हस्ताक्षरकर्ता की भूमिका हस्ताक्षर या अनुमोदन होनी चाहिए।',
      'send.sending': 'भेजा जा रहा है...',
      'send.detect_fields': 'फ़ील्ड स्वतः पहचानें',
      'send.detect_running': 'PDF स्कैन हो रहा है...',
      'send.detect_done': '{n} फ़ील्ड पहचाने और रखे गए।',
      'send.preferred_lang': 'पसंदीदा भाषा',

      'sign.title': 'दस्तावेज़ पर हस्ताक्षर करें',
      'sign.signing_as': 'हस्ताक्षर करने वाले',
      'sign.verify_id': 'अपनी पहचान सत्यापित करें',
      'sign.code_will_be_sent': 'आपके ईमेल पर एक सत्यापन कोड भेजा जाएगा।',
      'sign.send_code': 'सत्यापन कोड भेजें',
      'sign.resend_code': 'कोड पुनः भेजें',
      'sign.enter_code_to': 'इस पते पर भेजा गया 6-अंकीय कोड दर्ज करें:',
      'sign.review_doc': 'दस्तावेज़ की समीक्षा करें',
      'sign.draw_signature': 'अपना हस्ताक्षर बनाएँ',
      'sign.clear': 'साफ़ करें',
      'sign.draw_above': 'ऊपर अपना हस्ताक्षर बनाएँ',
      'sign.sign_btn': 'हस्ताक्षर करें',
      'sign.legal_disclaimer': 'हस्ताक्षर करके, आप सहमत हैं कि यह आपका क़ानूनी हस्ताक्षर है।',
      'sign.success': 'दस्तावेज़ पर हस्ताक्षर हो गए!',
      'sign.success_msg': 'आपका हस्ताक्षर दर्ज कर लिया गया है। दस्तावेज़ स्वामी को सूचित किया जाएगा।',
      'sign.success_msg_complete': 'सभी हस्ताक्षर एकत्र किए गए! सभी को हस्ताक्षरित दस्तावेज़ की एक प्रति प्राप्त होगी।',
      'sign.err_draw': 'कृपया ऊपर अपना हस्ताक्षर बनाएँ।',
      'sign.submitting': 'सबमिट हो रहा है...',
      'sign.fields_to_fill': 'भरने के लिए फ़ील्ड',
      'sign.required_completed': 'आवश्यक फ़ील्ड पूर्ण।',
      'sign.consent_title': 'इलेक्ट्रॉनिक हस्ताक्षर सहमति',
      'sign.consent_esign': 'मैं इस लेनदेन के लिए इलेक्ट्रॉनिक अभिलेखों और हस्ताक्षरों का उपयोग करने के लिए सहमति देता/देती हूँ। मैं समझता/समझती हूँ कि सूचना प्रौद्योगिकी अधिनियम, 2000 के अंतर्गत मेरा इलेक्ट्रॉनिक हस्ताक्षर क़ानूनी रूप से बाध्यकारी है।',
      'sign.consent_privacy': 'मैं स्वीकार करता/करती हूँ कि मेरा IP पता, ब्राउज़र, समय, ईमेल और (यदि दर्ज) फ़ोन/पहचान दस्तावेज़ ऑडिट ट्रेल के भाग के रूप में संग्रहीत किए जाएंगे (डीपीडीपी अधिनियम, 2023 के अनुसार)।',
      'sign.consent_accept': 'मैं सहमत हूँ',
      'sign.consent_decline': 'मैं सहमत नहीं हूँ',
      'sign.aadhaar_option': 'आधार से हस्ताक्षर करें',
      'sign.aadhaar_desc': 'अपना 12-अंकीय आधार संख्या उपयोग करें। आपके आधार-लिंक्ड मोबाइल पर OTP आएगा।',
      'sign.aadhaar_enter': 'अपना 12-अंकीय आधार संख्या दर्ज करें',
      'sign.aadhaar_otp': 'आधार-लिंक्ड मोबाइल पर भेजे गए OTP दर्ज करें',
      'sign.witness_title': 'साक्षी हस्ताक्षर',
      'sign.witness_confirm': 'मैं प्रमाणित करता/करती हूँ कि {name} ने मेरी उपस्थिति में इस दस्तावेज़ पर हस्ताक्षर किए।',

      'tpl.title': 'टेम्पलेट',
      'tpl.saved': 'सहेजे गए टेम्पलेट',
      'tpl.create': '+ दस्तावेज़ बनाएं (और टेम्पलेट के रूप में सहेजें)',
      'tpl.no_templates': 'अभी कोई टेम्पलेट नहीं',
      'tpl.no_templates_hint': 'हस्ताक्षर अनुरोध बनाएँ और "टेम्पलेट के रूप में सहेजें" पर टिक करें।',
      'tpl.use': 'उपयोग करें',
      'tpl.delete_confirm': 'टेम्पलेट "{name}" हटाएँ? यह पूर्ववत नहीं किया जा सकता।',
      'tpl.signers_n': 'हस्ताक्षरकर्ता',
      'tpl.pdf_included': 'PDF शामिल',
      'tpl.no_pdf': 'कोई PDF नहीं',
    },
  };

  const LANG_LABELS = { en: 'EN', fr: 'FR', hi: 'हि' };

  function detectLang() {
    try {
      const url = new URL(window.location.href);
      const qp = url.searchParams.get('lang');
      if (qp && dict[qp]) { try { localStorage.setItem(STORAGE_KEY, qp); } catch {} return qp; }
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored && dict[stored]) return stored;
    } catch {}
    const nav = (navigator.language || 'en').toLowerCase();
    if (nav.startsWith('fr')) return 'fr';
    if (nav.startsWith('hi')) return 'hi';
    return 'en';
  }

  let currentLang = detectLang();

  function t(key, vars) {
    let s = (dict[currentLang] && dict[currentLang][key]) || (dict.en[key]) || key;
    if (vars) for (const k in vars) s = s.replace('{' + k + '}', vars[k]);
    return s;
  }

  function applyTranslations(root) {
    (root || document).querySelectorAll('[data-i18n]').forEach(el => {
      el.textContent = t(el.dataset.i18n);
    });
    (root || document).querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      el.placeholder = t(el.dataset.i18nPlaceholder);
    });
    (root || document).querySelectorAll('[data-i18n-title]').forEach(el => {
      el.title = t(el.dataset.i18nTitle);
    });
    document.documentElement.lang = currentLang;
  }

  function setLang(lang) {
    if (!dict[lang]) return;
    currentLang = lang;
    try { localStorage.setItem(STORAGE_KEY, lang); } catch {}
    applyTranslations();
    window.dispatchEvent(new CustomEvent('certadocs:langchange', { detail: { lang } }));
  }

  function injectLanguageSwitcher() {
    if (document.getElementById('certadocs-lang-switcher')) return;
    const div = document.createElement('div');
    div.id = 'certadocs-lang-switcher';
    div.style.cssText = 'position:fixed;bottom:14px;right:14px;z-index:9999;background:white;border:1px solid #d0d5dd;border-radius:20px;padding:4px;box-shadow:0 1px 4px rgba(0,0,0,0.1);font-size:12px;display:flex;gap:2px;';
    Object.keys(dict).forEach(l => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = LANG_LABELS[l] || l.toUpperCase();
      b.style.cssText = 'border:none;background:transparent;padding:4px 10px;border-radius:14px;cursor:pointer;font-weight:600;color:#666;';
      if (l === currentLang) { b.style.background = '#1a3b7a'; b.style.color = 'white'; }
      b.addEventListener('click', () => {
        setLang(l);
        document.querySelectorAll('#certadocs-lang-switcher button').forEach(x => {
          x.style.background = 'transparent'; x.style.color = '#666';
        });
        b.style.background = '#1a3b7a'; b.style.color = 'white';
      });
      div.appendChild(b);
    });
    document.body.appendChild(div);
  }

  window.CertaDocsI18n = { t, setLang, applyTranslations, getLang: () => currentLang, availableLangs: () => Object.keys(dict) };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { applyTranslations(); injectLanguageSwitcher(); });
  } else {
    applyTranslations(); injectLanguageSwitcher();
  }
})();
