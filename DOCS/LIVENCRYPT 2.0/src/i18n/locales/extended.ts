import en from "./en.json";

type Locale = typeof en;
type Names = Locale["language"];
type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends Record<string, unknown> ? DeepPartial<T[K]> : T[K];
};

interface Pack {
  names: Names;
  c: Locale["common"];
  dashboard: Pick<Locale["dashboard"], "network" | "online" | "offline" | "settings" | "panic" | "panicTitle" | "help" | "helpTitle" | "initializingBootShield">;
  boot: Locale["boot"];
  settings: Locale["settings"];
  hardening: Locale["hardening"];
  textCipher: Locale["textCipher"];
  fileCipher: Locale["fileCipher"];
  templateEditor: Locale["templateEditor"];
  password: Locale["password"];
  tools: Locale["tools"];
}

function locale(pack: Pack): Locale {
  return {
    language: pack.names,
    common: pack.c,
    dashboard: {
      title: "LIVENCRYPT 2.0",
      ...pack.dashboard,
    },
    boot: pack.boot,
    settings: pack.settings,
    hardening: pack.hardening,
    textCipher: pack.textCipher,
    fileCipher: pack.fileCipher,
    templateEditor: pack.templateEditor,
    password: pack.password,
    tools: pack.tools,
  };
}

const names = {
  ru: { spanish: "Испанский", english: "Английский", chinese: "Китайский", russian: "Русский", portuguese: "Португальский", german: "Немецкий", french: "Французский", hindi: "Хинди", japanese: "Японский", korean: "Корейский", indonesian: "Индонезийский" },
  pt: { spanish: "Espanhol", english: "Inglês", chinese: "Chinês", russian: "Russo", portuguese: "Português", german: "Alemão", french: "Francês", hindi: "Hindi", japanese: "Japonês", korean: "Coreano", indonesian: "Indonésio" },
  de: { spanish: "Spanisch", english: "Englisch", chinese: "Chinesisch", russian: "Russisch", portuguese: "Portugiesisch", german: "Deutsch", french: "Französisch", hindi: "Hindi", japanese: "Japanisch", korean: "Koreanisch", indonesian: "Indonesisch" },
  fr: { spanish: "Espagnol", english: "Anglais", chinese: "Chinois", russian: "Russe", portuguese: "Portugais", german: "Allemand", french: "Français", hindi: "Hindi", japanese: "Japonais", korean: "Coréen", indonesian: "Indonésien" },
  hi: { spanish: "स्पेनी", english: "अंग्रेज़ी", chinese: "चीनी", russian: "रूसी", portuguese: "पुर्तगाली", german: "जर्मन", french: "फ़्रेंच", hindi: "हिन्दी", japanese: "जापानी", korean: "कोरियाई", indonesian: "इंडोनेशियाई" },
  ja: { spanish: "スペイン語", english: "英語", chinese: "中国語", russian: "ロシア語", portuguese: "ポルトガル語", german: "ドイツ語", french: "フランス語", hindi: "ヒンディー語", japanese: "日本語", korean: "韓国語", indonesian: "インドネシア語" },
  ko: { spanish: "스페인어", english: "영어", chinese: "중국어", russian: "러시아어", portuguese: "포르투갈어", german: "독일어", french: "프랑스어", hindi: "힌디어", japanese: "일본어", korean: "한국어", indonesian: "인도네시아어" },
  id: { spanish: "Spanyol", english: "Inggris", chinese: "Tionghoa", russian: "Rusia", portuguese: "Portugis", german: "Jerman", french: "Prancis", hindi: "Hindi", japanese: "Jepang", korean: "Korea", indonesian: "Indonesia" },
} satisfies Record<string, Names>;

const ru = locale({
  names: names.ru,
  c: { back: "НАЗАД", cancel: "ОТМЕНА", apply: "ПРИМЕНИТЬ", save: "СОХРАНИТЬ", create: "СОЗДАТЬ", edit: "ИЗМЕНИТЬ", delete: "УДАЛИТЬ", editing: "РЕДАКТИРУЕТСЯ", clean: "ОЧИСТИТЬ", close: "ЗАКРЫТЬ", verify: "ПРОВЕРИТЬ", processing: "ОБРАБОТКА...", execute: "ВЫПОЛНИТЬ", copy: "КОПИРОВАТЬ", box: "Ячейка {{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "СЕТЬ", online: "ОНЛАЙН", offline: "ОФЛАЙН", settings: "НАСТРОЙКИ", panic: "ПАНИКА", panicTitle: "Немедленно закрыть приложение", help: "ПОМОЩЬ", helpTitle: "Помощь для проверки доступа", initializingBootShield: "Инициализация Boot Shield..." },
  boot: { title: "LIVENCRYPT BOOT SHIELD", secureUnlockTitle: "РАЗБЛОКИРОВКА ЗАЩИЩЕННОЙ СРЕДЫ", secureUnlockSubtitle: "Введите разрешенную последовательность для расшифровки в памяти", boxes: "Последовательность ячеек (1-5):", primaryBoxPlaceholder: "C{{index}}", secondaryBoxPlaceholder: "B{{index}}", accessPhrase: "Фраза доступа:", accessPhrasePlaceholder: "Введите фразу для расшифровки...", secondaryBoxes: "Вторая последовательность ячеек:", secondaryPhrase: "Вторая фраза:", secondaryPhrasePlaceholder: "Введите вторую фразу...", unlock: "[ Разблокировать и загрузить в DRAM ]", resetInstall: "Сбросить локальную установку", resetWarning: "Удаляет vault Boot Shield и локальные шаблоны этого пользователя. Используйте только для чистой установки или если прежняя фраза утрачена.", resetConfirm: "RESTABLECER", resetAndClose: "[ Удалить локальный Boot Shield и закрыть ]", missingBoxes: "Нужно ввести все пять ячеек.", numericBoxes: "Ячейки должны быть числовыми.", boxRange: "Ячейки должны быть от 0 до 1000.", emptyPhrase: "Фраза доступа не может быть пустой.", emptySecondaryPhrase: "Вторая фраза доступа не может быть пустой.", invalidCredentials: "НЕВЕРНЫЕ УЧЕТНЫЕ ДАННЫЕ ИЛИ VAULT ИЗМЕНЕН.", logInit: "[СИСТЕМА] ИНИЦИАЛИЗАЦИЯ LIVENCRYPT CORE...", logShieldDetected: "[СИСТЕМА] НА ДИСКЕ ОБНАРУЖЕН АКТИВНЫЙ АВТО-ШИФР.", logEncryptedAccess: "[ВНИМАНИЕ] ДОСТУП К ПАНЕЛИ И ШАБЛОНАМ ПОЛНОСТЬЮ ЗАШИФРОВАН.", logEnterSequence: "[ВНИМАНИЕ] ВВЕДИТЕ ЯЧЕЙКИ + ФРАЗУ ДЛЯ МОНТИРОВАНИЯ СРЕДЫ В DRAM:", logNetworkChanged: "[СИСТЕМА] СОСТОЯНИЕ СЕТИ: {{state}}", logSuccessKeys: "[УСПЕХ] КЛЮЧИ ПРОВЕРЕНЫ.", logDecrypting: "[СИСТЕМА] РАСШИФРОВКА СЛОВАРЕЙ И ШАБЛОНОВ В DRAM... OK.", logGranted: "[СИСТЕМА] ДОСТУП РАЗРЕШЕН. ЗАГРУЗКА ИНТЕРФЕЙСА...", logRejected: "[ОТКАЗ] УЧЕТНЫЕ ДАННЫЕ ОТКЛОНЕНЫ. ДОСТУП ЗАПРЕЩЕН.", logReset: "[ВНИМАНИЕ] ЛОКАЛЬНЫЙ BOOT SHIELD СБРОШЕН. ЗАКРЫТИЕ..." },
  settings: { title: "НАСТРОЙКИ СИСТЕМЫ", languageSection: "Раздел: язык", languageSelect: "Выбрать язык:", accessSection: "Раздел: доступ", bootAutoEncrypt: "АВТО-ШИФРОВАНИЕ ПРИ ЗАПУСКЕ:", activate: "ВКЛЮЧИТЬ", deactivate: "ОТКЛЮЧИТЬ", bootShieldDescription: "Vault шифрует шаблоны через Argon2id + обязательный слой Livencrypt + XChaCha20-Poly1305. Фраза и ячейки не сохраняются в WebView.", bootTemplate: "Шаблон Boot Shield:", bootTemplateHelp: "Должен содержать HEX 0-9 и a-f. Выбранный шаблон хранится зашифрованным в vault.", doubleCredential: "Двойные учетные данные перед AEAD", boxes: "Последовательность ячеек:", bootPhrase: "Фраза шифрования:", bootPhrasePlaceholder: "Фраза авто-шифрования...", bootDisablePhrasePlaceholder: "Текущая фраза для отключения...", secondaryBoxes: "Вторая последовательность ячеек:", secondaryPhrase: "Вторая фраза:", secondaryPhrasePlaceholder: "Вторая фраза авто-шифрования...", processingVault: "[ ОБРАБОТКА ЗАШИФРОВАННОГО VAULT... ]", disableBootShield: "[ ПРОВЕРИТЬ И ОТКЛЮЧИТЬ BOOT SHIELD ]", createVault: "[ СОЗДАТЬ ЗАШИФРОВАННЫЙ VAULT И ЗАЩИТИТЬ ]", panicSection: "Раздел: разрушительная паника", destructivePanicMode: "Режим разрушительной паники:", destructivePanicDescription: "При включении панель показывает кнопку ? «Помощь для проверки доступа». Нажатие перезаписывает best-effort и удаляет vault, резервные копии, шаблоны и локальные данные пользователя.", inactivitySection: "Раздел: закрытие по бездействию", inactivityCloseMode: "Автоматическое закрытие при бездействии:", inactivitySeconds: "Секунд до закрытия:", inactivityDescription: "Если включено, любое окно Livencrypt закроет всё приложение после указанного времени без движения мыши, клавиатуры, прокрутки или взаимодействия.", networkSection: "Раздел: сеть", networkProfile: "Профиль управления сетью:", networkMock: "Безопасная симуляция", networkManual: "Внешний ручной", networkDropRoute: "Отключить Интернет без выключения интерфейсов", networkNmcliOff: "Выключить системную сеть", networkSave: "[ СОХРАНИТЬ ПРОФИЛЬ СЕТИ ]", networkHelp: "По умолчанию Livencrypt не отключает сеть. Реальные профили требуют ввода ENTENDIDO.", hardeningSection: "Раздел: hardening", bootEnabled: "Boot Shield включен", bootEnabledCloseText: "Зашифрованный vault создан и проверен. Livencrypt должен закрыться, чтобы при следующем запуске запросить 5 ячеек и фразу.", closing: "[ ЗАКРЫТИЕ LIVENCRYPT... ]", closeLivencrypt: "[ ЗАКРЫТЬ LIVENCRYPT ]", bootEnabledMessage: "Boot Shield включен. Закройте Livencrypt, чтобы при следующем запуске требовался зашифрованный доступ." },
  hardening: { coreDumps: "Core dumps", dumpable: "Dumpable", mlockall: "mlockall", integrity: "Целостность", blocked: "ЗАБЛОКИРОВАНО", no: "НЕТ", off: "OFF", failed: "ОШИБКА", noExpectedHash: "ОЖИДАЕМЫЙ HASH НЕ ЗАДАН", binarySha256: "SHA-256 бинарного файла", note: "Hardening применяется при запуске процесса, а не при разблокировке сессии. Core dumps, dumpable и mlockall применяются автоматически; целостность использует /etc/livencrypt/expected.sha256 или LIVENCRYPT_EXPECTED_SHA256.", noWarnings: "Предупреждений hardening нет.", unavailable: "Состояние hardening недоступно." },
  textCipher: { title: "ШИФРОВАТЬ ТЕКСТ", template: "Шаблон", encrypt: "ШИФРОВАТЬ", decrypt: "РАСШИФРОВАТЬ", text: "Текст", result: "Результат", textEncryptPlaceholder: "Введите текст для шифрования...", textDecryptPlaceholder: "Вставьте зашифрованный текст...", resultPlaceholder: "Результат...", insertPassword: "ВСТАВИТЬ ПАРОЛЬ", passwordDirectionTitle: "Пароль {{position}} символа", positionAfter: "после", positionBefore: "до", emptyText: "Пустой текст", selectTemplate: "Выберите шаблон", invalidBox: "Ячейка {{index}}: не число", boxOutOfRange: "Ячейка {{index}}: вне диапазона (0-1000)", passwordDetected: "Обнаружен пароль - требуется проверка", passwordRejected: "Пароль отклонен - результат скрыт", passwordVerified: "Пароль успешно проверен", operationOk: "{{operation}} OK ({{count}} симв.)", copied: "Скопировано в буфер", cleared: "Форма очищена" },
  fileCipher: { title: "ШИФРОВАТЬ ФАЙЛЫ", selectFile: "Выбрать файл", saveResult: "Сохранить результат", savePathPrompt: "Путь сохранения:", path: "Путь файла", pathPlaceholder: "/путь/к/файлу (или выберите папкой)", load: "ЗАГРУЗИТЬ", loading: "ЗАГРУЗКА...", name: "Имя:", bytes: "Байты:", reference: "Ссылка", referencePlaceholder: "текст ссылки (без пробелов)", executeSave: "ВЫПОЛНИТЬ И СОХРАНИТЬ", autoCloseAfterAction: "Закрыть Livencrypt после завершения", autoCloseAfterActionHelp: "Если включено, после шифрования или расшифровки файла приложение закрывается автоматически.", templatesGroup: "Шаблоны", missingTauri: "ОШИБКА: Tauri не обнаружен", missingPath: "Введите путь файла или выберите файл", loadError: "ОШИБКА загрузки: {{error}}", pathUnavailable: "Не удалось получить путь. Введите его вручную.", saveCancelled: "Сохранение отменено", encryptedAction: "ЗАШИФРОВАНО+СЖАТО", decryptedAction: "РАСПАКОВАНО+РАСШИФРОВАНО", windowCleared: "Окно очищено", openFolderTitle: "Открыть папку: {{path}}" },
  templateEditor: { ...en.templateEditor, title: "РЕДАКТОР ШАБЛОНОВ", selectLanguages: "Выбрать языки", numbersSigns: "Числа / знаки", newTemplate: "Новый шаблон", customSize: "Свой размер", addHexMinimum: "ДОБАВИТЬ HEX МИНИМУМ", shuffle: "СЛУЧАЙНО", palette: "Палитра символов", all: "ВСЕ", clearAll: "ОЧИСТИТЬ ВСЕ" },
  password: { ...en.password, setupTitle: "НАСТРОИТЬ ПАРОЛЬ", setupSubtitle: "Настройка режима пароля", lengthLimit: "Лимит символов пароля", lengthRangeLocalized: "(минимум {{min}}, максимум {{max}})", position: "Позиция пароля", afterSymbol: "После символа", beforeSymbol: "Перед символом", samplePassword: "пароль", controlSymbols: "Активные управляющие символы:", detectedTitle: "ПАРОЛЬ ОБНАРУЖЕН", verifyTitle: "ПРОВЕРКА ПАРОЛЯ", passwordLabel: "Пароль" },
  tools: { textTitle: "ТЕКСТОВЫЙ ТРАНСМУТАТОР", textDescription: "Позиционное шифрование и расшифровка текста с паролем и локальными шаблонами.", fileTitle: "ФАЙЛОВЫЙ ТРАНСМУТАТОР", fileDescription: "Шифрование и расшифровка файлов выбранным шаблоном.", templateTitle: "ШАБЛОНЫ", templateDescription: "Создание, редактирование и проверка алфавитов MessagePack." },
});

function fromEnglish(namesValue: Names, overrides: DeepPartial<Locale>): Locale {
  return {
    ...en,
    ...overrides,
    language: namesValue,
    common: { ...en.common, ...overrides.common },
    dashboard: { ...en.dashboard, ...overrides.dashboard },
    boot: { ...en.boot, ...overrides.boot },
    settings: { ...en.settings, ...overrides.settings },
    hardening: { ...en.hardening, ...overrides.hardening },
    textCipher: { ...en.textCipher, ...overrides.textCipher },
    fileCipher: { ...en.fileCipher, ...overrides.fileCipher },
    templateEditor: { ...en.templateEditor, ...overrides.templateEditor },
    password: { ...en.password, ...overrides.password },
    tools: { ...en.tools, ...overrides.tools },
  };
}

export const pt = fromEnglish(names.pt, {
  common: { back: "VOLTAR", cancel: "CANCELAR", apply: "APLICAR", save: "GUARDAR", create: "CRIAR", edit: "EDITAR", delete: "ELIMINAR", editing: "EDITANDO", clean: "LIMPAR", close: "FECHAR", verify: "VERIFICAR", processing: "PROCESSANDO...", execute: "EXECUTAR", copy: "COPIAR", box: "Caixa {{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "REDE", settings: "CONFIGURAÇÃO", panic: "PÂNICO", panicTitle: "Fechar a aplicação imediatamente", help: "AJUDA", helpTitle: "Ajuda para consultar o acesso", initializingBootShield: "Inicializando Boot Shield..." },
  boot: { secureUnlockTitle: "DESBLOQUEIO DO AMBIENTE SEGURO", secureUnlockSubtitle: "Introduza a sequência autorizada para decifrar em memória", boxes: "Sequência das caixas (1 a 5):", accessPhrase: "Frase de acesso:", accessPhrasePlaceholder: "Introduza a frase para decifrar...", secondaryBoxes: "Sequência secundária de caixas:", secondaryPhrase: "Frase secundária:", secondaryPhrasePlaceholder: "Introduza a segunda frase...", unlock: "[ Desbloquear e carregar na DRAM ]", missingBoxes: "Tem de introduzir as cinco caixas.", numericBoxes: "As caixas têm de ser numéricas.", boxRange: "As caixas têm de estar entre 0 e 1000.", emptyPhrase: "A frase de acesso não pode estar vazia.", emptySecondaryPhrase: "A segunda frase de acesso não pode estar vazia.", invalidCredentials: "CREDENCIAIS INVÁLIDAS OU VAULT MANIPULADO." },
  settings: { title: "CONFIGURAÇÃO DO SISTEMA", accessSection: "Secção: Acesso", activate: "ATIVAR", deactivate: "DESATIVAR", panicSection: "Secção: Pânico destrutivo", inactivitySection: "Secção: Fecho por inatividade", inactivityCloseMode: "Fecho automático por inatividade:", inactivitySeconds: "Segundos até fechar:", networkSection: "Secção: Rede", hardeningSection: "Secção: Hardening" },
  textCipher: { title: "CIFRAR TEXTO", template: "Modelo", encrypt: "CIFRAR", decrypt: "DECIFRAR", text: "Texto", result: "Resultado", emptyText: "Texto vazio", selectTemplate: "Selecione um modelo" },
  fileCipher: { title: "CIFRAR FICHEIROS", selectFile: "Selecionar ficheiro", saveResult: "Guardar resultado", path: "Caminho do ficheiro", reference: "Referência", executeSave: "EXECUTAR E GUARDAR", autoCloseAfterAction: "Fechar Livencrypt ao terminar" },
  password: { setupTitle: "CONFIGURAR PALAVRA-PASSE", lengthRangeLocalized: "(mínimo {{min}}, máximo {{max}})", samplePassword: "palavra-passe", detectedTitle: "PALAVRA-PASSE DETETADA", verifyTitle: "VERIFICAÇÃO DA PALAVRA-PASSE", passwordLabel: "Palavra-passe" },
  tools: { textTitle: "TRANSMUTADOR DE TEXTO", fileTitle: "TRANSMUTADOR DE FICHEIRO", templateTitle: "MODELOS" },
});

export const de = fromEnglish(names.de, {
  common: { back: "ZURÜCK", cancel: "ABBRECHEN", apply: "ANWENDEN", save: "SPEICHERN", create: "ERSTELLEN", edit: "BEARBEITEN", delete: "LÖSCHEN", editing: "BEARBEITUNG", clean: "LEEREN", close: "SCHLIESSEN", verify: "PRÜFEN", processing: "VERARBEITUNG...", execute: "AUSFÜHREN", copy: "KOPIEREN", box: "Feld {{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "NETZ", settings: "EINSTELLUNGEN", panic: "PANIK", panicTitle: "Anwendung sofort schließen", help: "HILFE", helpTitle: "Hilfe zum Zugriff", initializingBootShield: "Boot Shield wird initialisiert..." },
  boot: { secureUnlockTitle: "SICHERE UMGEBUNG ENTSPERREN", secureUnlockSubtitle: "Autorisierte Sequenz eingeben, um im Speicher zu entschlüsseln", boxes: "Feldsequenz (1 bis 5):", accessPhrase: "Zugriffsphrase:", accessPhrasePlaceholder: "Phrase zum Entschlüsseln eingeben...", secondaryBoxes: "Sekundäre Feldsequenz:", secondaryPhrase: "Sekundäre Phrase:", secondaryPhrasePlaceholder: "Zweite Phrase eingeben...", unlock: "[ Entsperren und in DRAM laden ]", missingBoxes: "Alle fünf Felder müssen eingegeben werden.", numericBoxes: "Felder müssen numerisch sein.", boxRange: "Felder müssen zwischen 0 und 1000 liegen.", emptyPhrase: "Die Zugriffsphrase darf nicht leer sein.", emptySecondaryPhrase: "Die zweite Zugriffsphrase darf nicht leer sein.", invalidCredentials: "UNGÜLTIGE ZUGANGSDATEN ODER MANIPULIERTER VAULT." },
  settings: { title: "SYSTEMEINSTELLUNGEN", accessSection: "Abschnitt: Zugriff", activate: "AKTIVIEREN", deactivate: "DEAKTIVIEREN", panicSection: "Abschnitt: Destruktive Panik", inactivitySection: "Abschnitt: Schließen bei Inaktivität", inactivityCloseMode: "Automatisch bei Inaktivität schließen:", inactivitySeconds: "Sekunden bis zum Schließen:", networkSection: "Abschnitt: Netzwerk", hardeningSection: "Abschnitt: Hardening" },
  textCipher: { title: "TEXT VERSCHLÜSSELN", template: "Vorlage", encrypt: "VERSCHLÜSSELN", decrypt: "ENTSCHLÜSSELN", text: "Text", result: "Ergebnis", emptyText: "Leerer Text", selectTemplate: "Vorlage auswählen" },
  fileCipher: { title: "DATEIEN VERSCHLÜSSELN", selectFile: "Datei auswählen", saveResult: "Ergebnis speichern", path: "Dateipfad", reference: "Referenz", executeSave: "AUSFÜHREN UND SPEICHERN", autoCloseAfterAction: "Livencrypt nach Abschluss schließen" },
  password: { setupTitle: "PASSWORT KONFIGURIEREN", lengthRangeLocalized: "(Minimum {{min}}, Maximum {{max}})", samplePassword: "Passwort", detectedTitle: "PASSWORT ERKANNT", verifyTitle: "PASSWORTPRÜFUNG", passwordLabel: "Passwort" },
  tools: { textTitle: "TEXT-TRANSMUTATOR", fileTitle: "DATEI-TRANSMUTATOR", templateTitle: "VORLAGEN" },
});

export const fr = fromEnglish(names.fr, {
  common: { back: "RETOUR", cancel: "ANNULER", apply: "APPLIQUER", save: "ENREGISTRER", create: "CRÉER", edit: "MODIFIER", delete: "SUPPRIMER", editing: "MODIFICATION", clean: "EFFACER", close: "FERMER", verify: "VÉRIFIER", processing: "TRAITEMENT...", execute: "EXÉCUTER", copy: "COPIER", box: "Case {{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "RÉSEAU", settings: "CONFIGURATION", panic: "PANIQUE", panicTitle: "Fermer immédiatement l'application", help: "AIDE", helpTitle: "Aide pour consulter l'accès", initializingBootShield: "Initialisation de Boot Shield..." },
  boot: { secureUnlockTitle: "DÉVERROUILLAGE DE L'ENVIRONNEMENT SÉCURISÉ", secureUnlockSubtitle: "Saisissez la séquence autorisée pour déchiffrer en mémoire", boxes: "Séquence des cases (1 à 5):", accessPhrase: "Phrase d'accès:", accessPhrasePlaceholder: "Saisissez la phrase pour déchiffrer...", secondaryBoxes: "Séquence secondaire de cases:", secondaryPhrase: "Phrase secondaire:", secondaryPhrasePlaceholder: "Saisissez la deuxième phrase...", unlock: "[ Déverrouiller et charger en DRAM ]", missingBoxes: "Vous devez saisir les cinq cases.", numericBoxes: "Les cases doivent être numériques.", boxRange: "Les cases doivent être entre 0 et 1000.", emptyPhrase: "La phrase d'accès ne peut pas être vide.", emptySecondaryPhrase: "La deuxième phrase d'accès ne peut pas être vide.", invalidCredentials: "IDENTIFIANTS INVALIDES OU VAULT MANIPULÉ." },
  settings: { title: "CONFIGURATION DU SYSTÈME", accessSection: "Section: Accès", activate: "ACTIVER", deactivate: "DÉSACTIVER", panicSection: "Section: Panique destructive", inactivitySection: "Section: Fermeture par inactivité", inactivityCloseMode: "Fermeture automatique par inactivité:", inactivitySeconds: "Secondes avant fermeture:", networkSection: "Section: Réseau", hardeningSection: "Section: Durcissement" },
  textCipher: { title: "CHIFFRER LE TEXTE", template: "Modèle", encrypt: "CHIFFRER", decrypt: "DÉCHIFFRER", text: "Texte", result: "Résultat", emptyText: "Texte vide", selectTemplate: "Sélectionnez un modèle" },
  fileCipher: { title: "CHIFFRER LES FICHIERS", selectFile: "Sélectionner un fichier", saveResult: "Enregistrer le résultat", path: "Chemin du fichier", reference: "Référence", executeSave: "EXÉCUTER ET ENREGISTRER", autoCloseAfterAction: "Fermer Livencrypt à la fin" },
  password: { setupTitle: "CONFIGURER LE MOT DE PASSE", lengthRangeLocalized: "(minimum {{min}}, maximum {{max}})", samplePassword: "motdepasse", detectedTitle: "MOT DE PASSE DÉTECTÉ", verifyTitle: "VÉRIFICATION DU MOT DE PASSE", passwordLabel: "Mot de passe" },
  tools: { textTitle: "TRANSMUTEUR DE TEXTE", fileTitle: "TRANSMUTEUR DE FICHIER", templateTitle: "MODÈLES" },
});

export const hi = fromEnglish(names.hi, {
  common: { back: "वापस", cancel: "रद्द", apply: "लागू करें", save: "सहेजें", create: "बनाएँ", edit: "संपादित करें", delete: "हटाएँ", editing: "संपादन", clean: "साफ़ करें", close: "बंद करें", verify: "सत्यापित करें", processing: "प्रक्रिया जारी...", execute: "चलाएँ", copy: "कॉपी", box: "बॉक्स {{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "नेटवर्क", settings: "सेटिंग्स", panic: "पैनिक", panicTitle: "एप्लिकेशन तुरंत बंद करें", help: "सहायता", helpTitle: "एक्सेस सहायता देखें", initializingBootShield: "Boot Shield प्रारंभ हो रहा है..." },
  boot: { secureUnlockTitle: "सुरक्षित वातावरण अनलॉक", secureUnlockSubtitle: "मेमोरी में डिक्रिप्ट करने के लिए अधिकृत क्रम दर्ज करें", boxes: "बॉक्स क्रम (1 से 5):", accessPhrase: "एक्सेस वाक्यांश:", accessPhrasePlaceholder: "डिक्रिप्ट करने के लिए वाक्यांश दर्ज करें...", secondaryBoxes: "दूसरा बॉक्स क्रम:", secondaryPhrase: "दूसरा वाक्यांश:", secondaryPhrasePlaceholder: "दूसरा वाक्यांश दर्ज करें...", unlock: "[ अनलॉक करें और DRAM में लोड करें ]", missingBoxes: "पाँचों बॉक्स दर्ज करना आवश्यक है.", numericBoxes: "बॉक्स संख्यात्मक होने चाहिए.", boxRange: "बॉक्स 0 से 1000 के बीच होने चाहिए.", emptyPhrase: "एक्सेस वाक्यांश खाली नहीं हो सकता.", emptySecondaryPhrase: "दूसरा एक्सेस वाक्यांश खाली नहीं हो सकता.", invalidCredentials: "अमान्य क्रेडेंशियल या बदला हुआ VAULT." },
  settings: { title: "सिस्टम सेटिंग्स", accessSection: "अनुभाग: एक्सेस", activate: "सक्रिय", deactivate: "निष्क्रिय", panicSection: "अनुभाग: विनाशकारी पैनिक", inactivitySection: "अनुभाग: निष्क्रियता पर बंद", inactivityCloseMode: "निष्क्रियता पर स्वतः बंद:", inactivitySeconds: "बंद होने तक सेकंड:", networkSection: "अनुभाग: नेटवर्क", hardeningSection: "अनुभाग: हार्डनिंग" },
  textCipher: { title: "टेक्स्ट एन्क्रिप्ट करें", template: "टेम्पलेट", encrypt: "एन्क्रिप्ट", decrypt: "डिक्रिप्ट", text: "टेक्स्ट", result: "परिणाम", emptyText: "खाली टेक्स्ट", selectTemplate: "टेम्पलेट चुनें" },
  fileCipher: { title: "फ़ाइलें एन्क्रिप्ट करें", selectFile: "फ़ाइल चुनें", saveResult: "परिणाम सहेजें", path: "फ़ाइल पथ", reference: "संदर्भ", executeSave: "चलाएँ और सहेजें", autoCloseAfterAction: "पूरा होने पर Livencrypt बंद करें" },
  password: { setupTitle: "पासवर्ड कॉन्फ़िगर करें", lengthRangeLocalized: "(न्यूनतम {{min}}, अधिकतम {{max}})", samplePassword: "पासवर्ड", detectedTitle: "पासवर्ड मिला", verifyTitle: "पासवर्ड सत्यापन", passwordLabel: "पासवर्ड" },
  tools: { textTitle: "टेक्स्ट ट्रांसम्यूटर", fileTitle: "फ़ाइल ट्रांसम्यूटर", templateTitle: "टेम्पलेट" },
});

export const ja = fromEnglish(names.ja, {
  common: { back: "戻る", cancel: "キャンセル", apply: "適用", save: "保存", create: "作成", edit: "編集", delete: "削除", editing: "編集中", clean: "クリア", close: "閉じる", verify: "検証", processing: "処理中...", execute: "実行", copy: "コピー", box: "ボックス{{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "ネットワーク", settings: "設定", panic: "パニック", panicTitle: "アプリケーションを直ちに閉じる", help: "ヘルプ", helpTitle: "アクセス確認ヘルプ", initializingBootShield: "Boot Shield を初期化中..." },
  boot: { secureUnlockTitle: "安全環境のロック解除", secureUnlockSubtitle: "メモリ内で復号するための認可シーケンスを入力してください", boxes: "ボックス順序（1から5）:", accessPhrase: "アクセスフレーズ:", accessPhrasePlaceholder: "復号用フレーズを入力...", secondaryBoxes: "第二ボックス順序:", secondaryPhrase: "第二フレーズ:", secondaryPhrasePlaceholder: "第二フレーズを入力...", unlock: "[ ロック解除して DRAM に読み込む ]", missingBoxes: "5つのボックスをすべて入力してください。", numericBoxes: "ボックスは数値である必要があります。", boxRange: "ボックスは0から1000の範囲です。", emptyPhrase: "アクセスフレーズは空にできません。", emptySecondaryPhrase: "第二アクセスフレーズは空にできません。", invalidCredentials: "認証情報が無効、または VAULT が改ざんされています。" },
  settings: { title: "システム設定", accessSection: "セクション: アクセス", activate: "有効", deactivate: "無効", panicSection: "セクション: 破壊的パニック", inactivitySection: "セクション: 無操作で閉じる", inactivityCloseMode: "無操作で自動終了:", inactivitySeconds: "終了までの秒数:", networkSection: "セクション: ネットワーク", hardeningSection: "セクション: 強化" },
  textCipher: { title: "テキストを暗号化", template: "テンプレート", encrypt: "暗号化", decrypt: "復号", text: "テキスト", result: "結果", emptyText: "空のテキスト", selectTemplate: "テンプレートを選択" },
  fileCipher: { title: "ファイルを暗号化", selectFile: "ファイルを選択", saveResult: "結果を保存", path: "ファイルパス", reference: "参照", executeSave: "実行して保存", autoCloseAfterAction: "完了後に Livencrypt を閉じる" },
  password: { setupTitle: "パスワード設定", lengthRangeLocalized: "（最小 {{min}}、最大 {{max}}）", samplePassword: "パスワード", detectedTitle: "パスワード検出", verifyTitle: "パスワード検証", passwordLabel: "パスワード" },
  tools: { textTitle: "テキスト変換器", fileTitle: "ファイル変換器", templateTitle: "テンプレート" },
});

export const ko = fromEnglish(names.ko, {
  common: { back: "뒤로", cancel: "취소", apply: "적용", save: "저장", create: "생성", edit: "편집", delete: "삭제", editing: "편집 중", clean: "지우기", close: "닫기", verify: "검증", processing: "처리 중...", execute: "실행", copy: "복사", box: "상자 {{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "네트워크", settings: "설정", panic: "패닉", panicTitle: "애플리케이션 즉시 닫기", help: "도움말", helpTitle: "접근 확인 도움말", initializingBootShield: "Boot Shield 초기화 중..." },
  boot: { secureUnlockTitle: "보안 환경 잠금 해제", secureUnlockSubtitle: "메모리에서 복호화할 승인된 순서를 입력하십시오", boxes: "상자 순서(1-5):", accessPhrase: "접근 문구:", accessPhrasePlaceholder: "복호화 문구 입력...", secondaryBoxes: "보조 상자 순서:", secondaryPhrase: "보조 문구:", secondaryPhrasePlaceholder: "두 번째 문구 입력...", unlock: "[ 잠금 해제 후 DRAM에 로드 ]", missingBoxes: "다섯 개 상자를 모두 입력해야 합니다.", numericBoxes: "상자는 숫자여야 합니다.", boxRange: "상자는 0에서 1000 사이여야 합니다.", emptyPhrase: "접근 문구는 비워 둘 수 없습니다.", emptySecondaryPhrase: "두 번째 접근 문구는 비워 둘 수 없습니다.", invalidCredentials: "잘못된 자격 증명 또는 변조된 VAULT입니다." },
  settings: { title: "시스템 설정", accessSection: "섹션: 접근", activate: "활성화", deactivate: "비활성화", panicSection: "섹션: 파괴적 패닉", inactivitySection: "섹션: 비활성 종료", inactivityCloseMode: "비활성 시 자동 종료:", inactivitySeconds: "종료까지 초:", networkSection: "섹션: 네트워크", hardeningSection: "섹션: 강화" },
  textCipher: { title: "텍스트 암호화", template: "템플릿", encrypt: "암호화", decrypt: "복호화", text: "텍스트", result: "결과", emptyText: "빈 텍스트", selectTemplate: "템플릿 선택" },
  fileCipher: { title: "파일 암호화", selectFile: "파일 선택", saveResult: "결과 저장", path: "파일 경로", reference: "참조", executeSave: "실행 및 저장", autoCloseAfterAction: "완료 후 Livencrypt 닫기" },
  password: { setupTitle: "비밀번호 설정", lengthRangeLocalized: "(최소 {{min}}, 최대 {{max}})", samplePassword: "비밀번호", detectedTitle: "비밀번호 감지됨", verifyTitle: "비밀번호 검증", passwordLabel: "비밀번호" },
  tools: { textTitle: "텍스트 변환기", fileTitle: "파일 변환기", templateTitle: "템플릿" },
});

export const id = fromEnglish(names.id, {
  common: { back: "KEMBALI", cancel: "BATAL", apply: "TERAPKAN", save: "SIMPAN", create: "BUAT", edit: "EDIT", delete: "HAPUS", editing: "MENGEDIT", clean: "BERSIHKAN", close: "TUTUP", verify: "VERIFIKASI", processing: "MEMPROSES...", execute: "JALANKAN", copy: "SALIN", box: "Kotak {{index}}", boxRangeSuffix: "(0-1000)" },
  dashboard: { network: "JARINGAN", settings: "PENGATURAN", panic: "PANIK", panicTitle: "Tutup aplikasi segera", help: "BANTUAN", helpTitle: "Bantuan untuk memeriksa akses", initializingBootShield: "Menginisialisasi Boot Shield..." },
  boot: { secureUnlockTitle: "BUKA KUNCI LINGKUNGAN AMAN", secureUnlockSubtitle: "Masukkan urutan resmi untuk mendekripsi di memori", boxes: "Urutan kotak (1 sampai 5):", accessPhrase: "Frasa akses:", accessPhrasePlaceholder: "Masukkan frasa untuk dekripsi...", secondaryBoxes: "Urutan kotak sekunder:", secondaryPhrase: "Frasa sekunder:", secondaryPhrasePlaceholder: "Masukkan frasa kedua...", unlock: "[ Buka kunci dan muat ke DRAM ]", missingBoxes: "Anda harus mengisi lima kotak.", numericBoxes: "Kotak harus berupa angka.", boxRange: "Kotak harus antara 0 dan 1000.", emptyPhrase: "Frasa akses tidak boleh kosong.", emptySecondaryPhrase: "Frasa akses kedua tidak boleh kosong.", invalidCredentials: "KREDENSIAL TIDAK VALID ATAU VAULT DIMANIPULASI." },
  settings: { title: "PENGATURAN SISTEM", accessSection: "Bagian: Akses", activate: "AKTIFKAN", deactivate: "NONAKTIFKAN", panicSection: "Bagian: Panik destruktif", inactivitySection: "Bagian: Tutup karena tidak aktif", inactivityCloseMode: "Tutup otomatis saat tidak aktif:", inactivitySeconds: "Detik sampai tutup:", networkSection: "Bagian: Jaringan", hardeningSection: "Bagian: Hardening" },
  textCipher: { title: "ENKRIPSI TEKS", template: "Templat", encrypt: "ENKRIPSI", decrypt: "DEKRIPSI", text: "Teks", result: "Hasil", emptyText: "Teks kosong", selectTemplate: "Pilih templat" },
  fileCipher: { title: "ENKRIPSI FILE", selectFile: "Pilih file", saveResult: "Simpan hasil", path: "Jalur file", reference: "Referensi", executeSave: "JALANKAN DAN SIMPAN", autoCloseAfterAction: "Tutup Livencrypt setelah selesai" },
  password: { setupTitle: "KONFIGURASI KATA SANDI", lengthRangeLocalized: "(minimum {{min}}, maksimum {{max}})", samplePassword: "katasandi", detectedTitle: "KATA SANDI TERDETEKSI", verifyTitle: "VERIFIKASI KATA SANDI", passwordLabel: "Kata sandi" },
  tools: { textTitle: "TRANSMUTATOR TEKS", fileTitle: "TRANSMUTATOR FILE", templateTitle: "TEMPLAT" },
});

export { ru };
