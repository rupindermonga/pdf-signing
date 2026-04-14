// SealForge i18n — lightweight client-side translations (EN + FR)
(function () {
  const STORAGE_KEY = 'sealforge_lang';

  const dict = {
    en: {
      // Common
      'app.title': 'SealForge',
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

      // Login
      'login.title': 'Sign in to SealForge',
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
      'send.signer_hint': 'Drag the handle to reorder. Roles: Sign (signs), Approve (approves & signs), CC (notified at completion only).',
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
      'send.err_min_signer': 'Add at least one signer with name and email.',
      'send.err_no_pdf': 'Please upload a PDF.',
      'send.err_min_signing_role': 'At least one signer must have role Sign or Approve.',
      'send.sending': 'Sending...',

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
      // Common
      'app.title': 'SealForge',
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

      // Login
      'login.title': 'Connexion à SealForge',
      'login.subtitle': 'Connexion sans mot de passe par courriel.',
      'login.email_placeholder': 'vous@exemple.com',
      'login.send_code': 'Envoyer le code',
      'login.code_sent': 'Un code à 6 chiffres a été envoyé. Saisissez-le ci-dessous.',
      'login.code_placeholder': '------',
      'login.verify': 'Vérifier',
      'login.name_placeholder': 'Votre nom complet (première fois seulement)',
      'login.invalid_code': 'Code invalide ou expiré.',

      // Dashboard
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

      // Send
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
      'send.signer_hint': 'Glissez la poignée pour réorganiser. Rôles : Signer, Approuver, CC (notifié à la fin seulement).',
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
      'send.err_min_signer': 'Ajoutez au moins un signataire avec nom et courriel.',
      'send.err_no_pdf': 'Veuillez téléverser un PDF.',
      'send.err_min_signing_role': 'Au moins un signataire doit avoir le rôle Signer ou Approuver.',
      'send.sending': 'Envoi en cours...',

      // Sign
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

      // Templates
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
  };

  function detectLang() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored && dict[stored]) return stored;
    } catch {}
    const nav = (navigator.language || 'en').toLowerCase();
    return nav.startsWith('fr') ? 'fr' : 'en';
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
    window.dispatchEvent(new CustomEvent('sealforge:langchange', { detail: { lang } }));
  }

  function injectLanguageSwitcher() {
    if (document.getElementById('sealforge-lang-switcher')) return;
    const div = document.createElement('div');
    div.id = 'sealforge-lang-switcher';
    div.style.cssText = 'position:fixed;bottom:14px;right:14px;z-index:9999;background:white;border:1px solid #d0d5dd;border-radius:20px;padding:4px;box-shadow:0 1px 4px rgba(0,0,0,0.1);font-size:12px;display:flex;gap:2px;';
    ['en', 'fr'].forEach(l => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = l.toUpperCase();
      b.style.cssText = 'border:none;background:transparent;padding:4px 10px;border-radius:14px;cursor:pointer;font-weight:600;color:#666;';
      if (l === currentLang) { b.style.background = '#1a3b7a'; b.style.color = 'white'; }
      b.addEventListener('click', () => {
        setLang(l);
        document.querySelectorAll('#sealforge-lang-switcher button').forEach(x => {
          x.style.background = 'transparent'; x.style.color = '#666';
        });
        b.style.background = '#1a3b7a'; b.style.color = 'white';
      });
      div.appendChild(b);
    });
    document.body.appendChild(div);
  }

  window.SealForgeI18n = { t, setLang, applyTranslations, getLang: () => currentLang };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { applyTranslations(); injectLanguageSwitcher(); });
  } else {
    applyTranslations(); injectLanguageSwitcher();
  }
})();
