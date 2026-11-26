//! Five-language localization (`fa`, `en`, `la`, `zh`, `ru`) for `agy-telegram`.
//!
//! Order in translation arrays is strictly `[Fa, En, La, Zh, Ru]`, guaranteeing at compile time
//! that every UI string has an explicit translation in all five languages.

use agy_core::acl::{AclStore, RoleTier};
use agy_core::store::StateStore;
use serde_json::json;

use crate::ctx::BotCtx;

/// Supported UI languages (user-selectable via `/lang` or Dashboard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Lang {
    Fa,
    #[default]
    En,
    La,
    Zh,
    Ru,
}

impl Lang {
    pub const ALL: [Lang; 5] = [Lang::Fa, Lang::En, Lang::La, Lang::Zh, Lang::Ru];

    #[inline]
    pub const fn idx(self) -> usize {
        match self {
            Self::Fa => 0,
            Self::En => 1,
            Self::La => 2,
            Self::Zh => 3,
            Self::Ru => 4,
        }
    }

    pub const fn code(self) -> &'static str {
        match self {
            Self::Fa => "fa",
            Self::En => "en",
            Self::La => "la",
            Self::Zh => "zh",
            Self::Ru => "ru",
        }
    }

    pub const fn native_label(self) -> &'static str {
        match self {
            Self::Fa => "🇮🇷 فارسی",
            Self::En => "🇬🇧 English",
            Self::La => "🏛 Latina",
            Self::Zh => "🇨🇳 简体中文",
            Self::Ru => "🇷🇺 Русский",
        }
    }

    pub const fn is_rtl(self) -> bool {
        matches!(self, Self::Fa)
    }

    pub fn from_code(s: &str) -> Option<Self> {
        let low = s.trim().to_ascii_lowercase();
        let primary = low.split(['-', '_']).next().unwrap_or(low.as_str());
        match primary {
            "fa" | "persian" | "farsi" => Some(Self::Fa),
            "en" | "english" => Some(Self::En),
            "la" | "lat" | "latin" | "latina" => Some(Self::La),
            "zh" | "cn" | "chs" | "chinese" => Some(Self::Zh),
            "ru" | "rus" | "russian" => Some(Self::Ru),
            _ => None,
        }
    }

    pub fn from_tg_language_code(s: &str) -> Option<Self> {
        Self::from_code(s)
    }
}

/// Translation catalog keys. Every variant maps to `[Fa, En, La, Zh, Ru]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tx {
    // --- Tiers & Status ---
    TierUser,
    TierAdmin,
    TierOwner,
    StatusRunning,
    StatusIdle,
    EnabledWord,
    DisabledWord,
    NoneWord,

    // --- Buttons ---
    BtnMenu,
    BtnNewChat,
    BtnModel,
    BtnUncensored,
    BtnGrok,
    BtnStatus,
    BtnMcp,
    BtnSkills,
    BtnSettings,
    BtnHelp,
    BtnStop,
    BtnSessions,
    BtnUsers,
    BtnAccounts,
    BtnSecretary,
    BtnWidgets,
    BtnLanguage,
    BtnRefresh,
    BtnCwd,
    BtnNetwork,
    BtnCron,
    BtnProxies,
    BtnPolicy,
    BtnAutomations,
    MenuTabAi,
    MenuTabTools,
    MenuTabAdmin,

    // --- Access Control / Auth ---
    OwnerOnly,
    ModuleRequiredHdr,
    RootRequiredHint,
    ApprovedMinimalWelcome,
    ApprovedDashboardWelcome,

    // --- Minimal Chat-Only Card & Dashboard ---
    MinimalChatTitle,
    MinimalChatHint,
    MinimalChatFooter,
    DashTitle,
    DashFieldEngine,
    DashFieldModel,
    DashFieldMode,
    DashFieldEffort,
    DashFieldWorkspace,
    DashFieldSession,
    DashFieldStatus,
    DashFieldModules,
    DashSendTip,

    // --- Language Picker ---
    LangTitle,
    LangCurrentLabel,
    LangSelectHint,
    LangUpdatedToast,
    LangInvalidArg,

    // --- Help ---
    HelpHeader,
    HelpSecChat,
    HelpSecModules,
    HelpSecAdmin,
    HelpSecOwner,
    HelpFooterTip,

    // --- Generic Handler Feedback ---
    NewChatStarted,
    StoppingTask,
    NoRunningTask,
    CancellingInput,
    NothingToCancel,
    WorkingNotice,
    QueuedNotice,
    QueueBusyNotice,
    EmptyReplyNotice,

    // --- Panels & Module Headers ---
    PanelModelsTitle,
    PanelUncensoredTitle,
    PanelGrokTitle,
    PanelStatusTitle,
    PanelSettingsTitle,
    PanelAdvancedTitle,
    PanelSessionsTitle,
    PanelCwdTitle,
    PanelAgentTitle,
    PanelChangelogTitle,
    PanelNetTitle,
    PanelCronTitle,
    PanelSkillsTitle,
    PanelMcpTitle,
    PanelWidgetsTitle,
    PanelUsersTitle,
    PanelProxiesTitle,

    // --- Startup & File Upload ---
    StartupConnectedTitle,
    StartupTip,
    FileRejectedSize,
    FileDownloadFailed,
    FileSavedHeading,
}

#[inline]
pub const fn t(lang: Lang, key: Tx) -> &'static str {
    let arr: [&'static str; 5] = match key {
        // --- Tiers & Status ---
        Tx::TierUser => ["کاربر", "User", "Usor", "用户", "Пользователь"],
        Tx::TierAdmin => ["ادمین", "Admin", "Administrator", "管理员", "Админ"],
        Tx::TierOwner => ["مالک (Owner)", "Owner", "Dominus", "所有者", "Владелец"],
        Tx::StatusRunning => ["در حال اجرا", "running", "currens", "运行中", "выполняется"],
        Tx::StatusIdle => ["آماده", "idle", "otiatus", "空闲", "ожидание"],
        Tx::EnabledWord => ["فعال", "enabled", "activum", "已启用", "включено"],
        Tx::DisabledWord => ["غیرفعال", "disabled", "inactivum", "已禁用", "отключено"],
        Tx::NoneWord => ["ندارد", "none", "nullum", "无", "нет"],

        // --- Buttons ---
        Tx::BtnMenu => ["منو", "Menu", "Tabula", "主菜单", "Меню"],
        Tx::BtnNewChat => ["گفتگوی جدید", "New chat", "Nova colloquia", "新对话", "Новый чат"],
        Tx::BtnModel => ["مدل", "Model", "Exemplar", "模型", "Модель"],
        Tx::BtnUncensored => ["وب مدل", "Web Model", "Web Model", "Web 模型", "Web-модель"],
        Tx::BtnGrok => ["گراک", "Grok", "Grok", "Grok 模型", "Grok"],
        Tx::BtnStatus => ["وضعیت", "Status", "Status", "状态", "Статус"],
        Tx::BtnMcp => ["ابزارهای MCP", "MCPs", "MCP", "MCP 服务", "MCP"],
        Tx::BtnSkills => ["مهارت‌ها", "Skills", "Artes", "技能库", "Навыки"],
        Tx::BtnSettings => ["تنظیمات", "Settings", "Optiones", "设置", "Настройки"],
        Tx::BtnHelp => ["راهنما", "Help", "Auxilium", "帮助", "Помощь"],
        Tx::BtnStop => ["توقف", "Stop", "Siste", "停止", "Стоп"],
        Tx::BtnSessions => ["نشست‌ها", "Sessions", "Sessiones", "会话历史", "Сессии"],
        Tx::BtnUsers => ["کاربران", "Users", "Usores", "用户管理", "Пользователи"],
        Tx::BtnAccounts => ["اکانت‌ها", "Accounts", "Rationes", "账号池", "Аккаунты"],
        Tx::BtnSecretary => ["منشی هوشمند", "Secretary", "Scriba", "智能秘书", "Секретарь"],
        Tx::BtnWidgets => ["ویجت‌ها", "Widgets", "Instrumenta", "交互组件", "Виджеты"],
        Tx::BtnLanguage => ["زبان", "Language", "Lingua", "语言", "Язык"],
        Tx::BtnRefresh => ["بروزرسانی", "Refresh", "Renova", "刷新", "Обновить"],
        Tx::BtnCwd => ["پوشه کاری", "Workspace", "Officina", "工作目录", "Папка"],
        Tx::BtnNetwork => ["شبکه", "Network", "Rete", "网络状态", "Сеть"],
        Tx::BtnCron => ["کرون", "Cron", "Horarium", "计划任务", "Крон"],
        Tx::BtnProxies => ["پروکسی‌ها", "Proxies", "Vicarii", "代理池", "Прокси"],
        Tx::BtnPolicy => ["سیاست ایمنی", "Safety Policy", "Consilium", "安全策略", "Политика"],
        Tx::BtnAutomations => ["اتوماسیون", "Automations", "Automata", "定时任务", "Автозадачи"],
        Tx::MenuTabAi => ["گفتگو", "AI & Chat", "Colloquium", "对话", "Чат"],
        Tx::MenuTabTools => ["ابزار و شبکه", "Tools & Net", "Instrumenta", "工具网络", "Инструменты"],
        Tx::MenuTabAdmin => ["مدیریت", "Admin", "Administratio", "管理", "Управление"],

        // --- Access Control / Auth ---
        Tx::OwnerOnly => [
            "این بخش فقط برای مالک (Owner) در دسترس است.",
            "Owner-only command.",
            "Hoc mandatum soli Domino reservatur.",
            "此功能仅限所有者使用。",
            "Команда доступна только владельцу.",
        ],
        Tx::ModuleRequiredHdr => [
            "دسترسی به این ماژول غیرفعال است:",
            "Module permission required:",
            "Permissio huius moduli requiritur:",
            "需要启用该模块权限：",
            "Требуется разрешение модуля:",
        ],
        Tx::RootRequiredHint => [
            "نیاز به دسترسی روت (Root Access) دارد.",
            "Requires root access permission.",
            "Accessum radicem (Root Access) requirit.",
            "需要 Root 权限才能执行此操作。",
            "Требуется доступ root (Root Access).",
        ],
        Tx::ApprovedMinimalWelcome => [
            "دسترسی چت تایید شد. پیام خود را ارسال کنید یا از <code>/lang</code> و <code>/help</code> استفاده کنید.",
            "Chat access approved. Send any message to begin, or use <code>/lang</code> and <code>/help</code>.",
            "Accessus colloquii probatus est. Mitte nuntium vel utere <code>/lang</code> et <code>/help</code>.",
            "对话权限已批准。直接发送消息即可开始对话，或使用 <code>/lang</code> 与 <code>/help</code>。",
            "Доступ к чату одобрен. Отправьте сообщение или используйте <code>/lang</code> и <code>/help</code>.",
        ],
        Tx::ApprovedDashboardWelcome => [
            "دسترسی تایید شد. از <code>/menu</code> برای باز کردن داشبورد یا از چت مستقیم استفاده کنید.",
            "Access approved. Tap <code>/menu</code> to open your dashboard or send any message.",
            "Accessus probatus est. Preme <code>/menu</code> pro tabula vel mitte nuntium.",
            "权限已批准。使用 <code>/menu</code> 打开控制面板，或直接发送消息。",
            "Доступ одобрен. Нажмите <code>/menu</code> для панели управления или отправьте сообщение.",
        ],

        // --- Minimal Chat Card & Dashboard ---
        Tx::MinimalChatTitle => [
            "گفتگوی آنتی‌گراویتی",
            "Antigravity Chat",
            "Colloquium Antigravity",
            "Antigravity 对话",
            "Чат Antigravity",
        ],
        Tx::MinimalChatHint => [
            "حساب شما در حالت چت ساده است (داشبورد غیرفعال). کافیست پیام، کد یا فایل خود را ارسال کنید.",
            "Chat-only access is active (dashboard hidden). Send any message, code, or file.",
            "Modus colloquii simplicis activus est (tabula celata). Mitte nuntium vel fasciculum.",
            "当前为纯对话模式（仪表盘未启用）。直接发送消息或文件即可。",
            "Активен режим простого чата (панель скрыта). Просто отправьте сообщение или файл.",
        ],
        Tx::MinimalChatFooter => [
            "فرمان‌ها: /new · /lang · /stop · /help",
            "Commands: /new · /lang · /stop · /help",
            "Mandata: /new · /lang · /stop · /help",
            "可用命令: /new · /lang · /stop · /help",
            "Команды: /new · /lang · /stop · /help",
        ],
        Tx::DashTitle => [
            "داشبورد آنتی‌گراویتی",
            "Antigravity Dashboard",
            "Tabula Antigravity",
            "Antigravity 控制面板",
            "Панель Antigravity",
        ],
        Tx::DashFieldEngine => ["موتور", "Engine", "Machina", "引擎", "Движок"],
        Tx::DashFieldModel => ["مدل", "Model", "Exemplar", "模型", "Модель"],
        Tx::DashFieldMode => ["حالت", "Mode", "Modus", "模式", "Режим"],
        Tx::DashFieldEffort => ["تلاش استدلال", "Effort", "Vis", "推理深度", "Глубина"],
        Tx::DashFieldWorkspace => ["پوشه کاری", "Workspace", "Officina", "工作区", "Папка"],
        Tx::DashFieldSession => ["نشست", "Session", "Sessio", "会话", "Сессия"],
        Tx::DashFieldStatus => ["وضعیت", "Status", "Status", "状态", "Статус"],
        Tx::DashFieldModules => ["ماژول‌ها", "Modules", "Moduli", "已授权模块", "Модули"],
        Tx::DashSendTip => [
            "برای گفتگو پیام یا فایل ارسال کنید.",
            "Send a message or file to talk.",
            "Mitte nuntium vel fasciculum ad colloquendum.",
            "发送消息或文件即可开始对话。",
            "Отправьте сообщение или файл для общения.",
        ],

        // --- Language Picker ---
        Tx::LangTitle => [
            "انتخاب زبان ربات",
            "Bot Language",
            "Lingua Instrumenti",
            "选择机器人语言",
            "Язык интерфейса",
        ],
        Tx::LangCurrentLabel => [
            "زبان فعلی",
            "Current language",
            "Lingua praesens",
            "当前语言",
            "Текущий язык",
        ],
        Tx::LangSelectHint => [
            "زبان دلخواه خود را انتخاب کنید (منو و دستورات اسلش بلافاصله بروزرسانی می‌شوند):",
            "Choose your preferred language (menus and slash commands update immediately):",
            "Elige linguam optatam (tabulae et mandata statim renovantur):",
            "选择您的首选语言（界面按钮和斜杠命令将立即同步更新）：",
            "Выберите предпочитаемый язык (меню и команды обновятся мгновенно):",
        ],
        Tx::LangUpdatedToast => [
            "زبان به فارسی تغییر یافت",
            "Language set to English",
            "Lingua ad Latinam mutata est",
            "语言已切换为简体中文",
            "Язык переключён на русский",
        ],
        Tx::LangInvalidArg => [
            "کد زبان نامعتبر است. گزینه‌ها: fa, en, la, zh, ru",
            "Unknown language code. Use: fa, en, la, zh, ru",
            "Codex linguae ignotus. Utere: fa, en, la, zh, ru",
            "未知语言代码。支持: fa, en, la, zh, ru",
            "Неверный код языка. Доступно: fa, en, la, zh, ru",
        ],

        // --- Help ---
        Tx::HelpHeader => [
            "راهنمای دستورات",
            "Command Reference",
            "Index Mandatorum",
            "命令参考手册",
            "Справочник команд",
        ],
        Tx::HelpSecChat => [
            "گفتگو و کنترل پایه",
            "Chat & Core",
            "Colloquium et Fundamenta",
            "对话与基础控制",
            "Чат и управление",
        ],
        Tx::HelpSecModules => [
            "ماژول‌های فعال شما",
            "Enabled Modules",
            "Moduli Activi",
            "已启用的功能模块",
            "Доступные модули",
        ],
        Tx::HelpSecAdmin => [
            "دسترسی ادمین و روت",
            "Admin / Root Capabilities",
            "Potestas Administratoris",
            "管理员 / Root 权限",
            "Права администратора и Root",
        ],
        Tx::HelpSecOwner => [
            "کنترل اختصاصی مالک (Owner)",
            "Owner Control",
            "Imperium Domini",
            "所有者专属控制",
            "Управление владельца",
        ],
        Tx::HelpFooterTip => [
            "برای گفتگو کافیست متن، کد یا فایل خود را ارسال کنید.",
            "Send any text, code, voice, image, or file directly to chat.",
            "Mitte textum, codicem aut fasciculum directe ad respondendum.",
            "直接发送文本、代码或文件即可开始交互。",
            "Просто отправьте текст, код или файл для работы с ассистентом.",
        ],

        // --- Generic Handler Feedback ---
        Tx::NewChatStarted => [
            "گفتگوی جدید آغاز شد.",
            "New chat started.",
            "Novum colloquium inceptum est.",
            "已开启新对话。",
            "Начат новый чат.",
        ],
        Tx::StoppingTask => [
            "در حال توقف تسک فعال...",
            "Stopping active task...",
            "Opus currens sistitur...",
            "正在停止当前任务...",
            "Остановка текущей задачи...",
        ],
        Tx::NoRunningTask => [
            "هیچ تسکی در حال اجرا نیست.",
            "No running task.",
            "Nullum opus nunc currit.",
            "当前没有正在运行的任务。",
            "Нет активных задач.",
        ],
        Tx::CancellingInput => [
            "ورودی در حال انتظار لغو شد.",
            "Pending input cancelled.",
            "Ingressus exspectans abrogatus est.",
            "已取消当前输入等待。",
            "Ожидание ввода отменено.",
        ],
        Tx::NothingToCancel => [
            "موردی برای لغو وجود ندارد.",
            "Nothing to cancel.",
            "Nihil est quod abrogetur.",
            "当前没有可取消的操作。",
            "Нечего отменять.",
        ],
        Tx::WorkingNotice => [
            "در حال پردازش...",
            "Working...",
            "Laboratur...",
            "处理中...",
            "Выполняется...",
        ],
        Tx::QueuedNotice => [
            "در صف انتظار قرار گرفت.",
            "Queued behind active task.",
            "In ordine post opus currens positum.",
            "已加入队列等待处理。",
            "Добавлено в очередь.",
        ],
        Tx::QueueBusyNotice => [
            "صف چت پر است؛ پس از پایان تسک فعلی دوباره تلاش کنید.",
            "Session queue is busy; try again after current run.",
            "Ordo plenus est; iterum tenta post opus currens.",
            "当前队列已满，请等待任务完成后重试。",
            "Очередь переполнена, повторите после завершения текущей задачи.",
        ],
        Tx::EmptyReplyNotice => [
            "پاسخ خالی دریافت شد.",
            "Empty response.",
            "Responsum vacuum.",
            "收到空响应。",
            "Получен пустой ответ.",
        ],

        // --- Panel Titles ---
        Tx::PanelModelsTitle => [
            "انتخاب مدل Antigravity",
            "Choose Antigravity Model",
            "Elige Exemplar Antigravity",
            "选择 Antigravity 模型",
            "Выбор модели Antigravity",
        ],
        Tx::PanelUncensoredTitle => [
            "ونیس بدون سانسور (Agent / Chat)",
            "Venice Uncensored (Agent / Chat)",
            "Venice Libera (Agens / Colloquium)",
            "Venice 无审查模式 (智能体 / 对话)",
            "Venice Без цензуры (Агент / Чат)",
        ],
        Tx::PanelGrokTitle => [
            "گراک اشتراکی و مدل‌ها",
            "Grok Subscription & Models",
            "Grok Subscriptio et Exemplaria",
            "Grok 订阅与模型",
            "Подписка и модели Grok",
        ],
        Tx::PanelStatusTitle => [
            "وضعیت سیستم و موتور",
            "System & Engine Status",
            "Status Systematis",
            "系统与引擎状态",
            "Статус системы",
        ],
        Tx::PanelSettingsTitle => [
            "تنظیمات و کنترل‌های عملیاتی",
            "Settings & Controls",
            "Optiones et Moderatio",
            "设置与运行控制",
            "Настройки и управление",
        ],
        Tx::PanelAdvancedTitle => [
            "تنظیمات پیشرفته",
            "Advanced Settings",
            "Optiones Provectiores",
            "高级设置",
            "Расширенные настройки",
        ],
        Tx::PanelSessionsTitle => [
            "نشست‌های گفتگو",
            "Sessions",
            "Sessiones",
            "对话历史会话",
            "Сессии чата",
        ],
        Tx::PanelCwdTitle => [
            "پوشه کاری (Workspace)",
            "Workspace Directory",
            "Directorium Officinae",
            "工作目录管理",
            "Рабочая директория",
        ],
        Tx::PanelAgentTitle => [
            "ایجنت سفارشی",
            "Custom Agent",
            "Agens Proprius",
            "自定义智能体",
            "Пользовательский агент",
        ],
        Tx::PanelChangelogTitle => [
            "تغییرات نسخه agy",
            "agy Release Notes",
            "Notae Editionis agy",
            "agy 版本更新日志",
            "Журнал изменений agy",
        ],
        Tx::PanelNetTitle => [
            "سلامت شبکه و پروکسی",
            "Network & Proxy Health",
            "Valetudo Retis et Vicarii",
            "网络与代理状态",
            "Состояние сети и прокси",
        ],
        Tx::PanelCronTitle => [
            "وظایف زمان‌بندی‌شده (Cron)",
            "Scheduled Sync Jobs",
            "Opera Temporaria (Cron)",
            "定时同步任务",
            "Планировщик задач (Cron)",
        ],
        Tx::PanelSkillsTitle => [
            "مدیریت مهارت‌ها (Skills)",
            "Skills Manager",
            "Procurator Artium",
            "技能库管理",
            "Менеджер навыков",
        ],
        Tx::PanelMcpTitle => [
            "سرورهای MCP",
            "MCP Servers",
            "Servitores MCP",
            "MCP 服务器管理",
            "Серверы MCP",
        ],
        Tx::PanelWidgetsTitle => [
            "ویجت‌های تعاملی",
            "Interactive Widgets",
            "Instrumenta Interactiva",
            "交互式小部件",
            "Интерактивные виджеты",
        ],
        Tx::PanelUsersTitle => [
            "مدیریت کاربران، سطوح و ماژول‌ها",
            "Users, Tiers & Modules",
            "Usores, Gradus et Moduli",
            "用户、等级与模块权限",
            "Пользователи, уровни и модули",
        ],
        Tx::PanelProxiesTitle => [
            "مدیریت پروکسی‌ها و شبکه خروجی",
            "Proxies & Egress Network",
            "Vicarii et Rete",
            "代理池与出口网络",
            "Прокси и выходная сеть",
        ],

        // --- Startup & File Upload ---
        Tx::StartupConnectedTitle => [
            "آنتی‌گراویتی متصل شد",
            "Antigravity connected",
            "Antigravity coniunctum est",
            "Antigravity 已上线连接",
            "Antigravity подключён",
        ],
        Tx::StartupTip => [
            "نوتیفیکیشن‌های سیستم و آپدیت فقط برای مالک ارسال می‌شوند.",
            "System and update alerts are delivered exclusively to Owner.",
            "Monitiones systematis soli Domino mittuntur.",
            "系统与更新通知仅发送给所有者。",
            "Системные уведомления и обновления отправляются только владельцу.",
        ],
        Tx::FileRejectedSize => [
            "فایل از حد مجاز ۲۰ مگابایت بزرگ‌تر است.",
            "File exceeds the 20 MB limit.",
            "Fasciculus modum 20 MB excedit.",
            "文件大小超过 20 MB 限制。",
            "Файл превышает лимит в 20 МБ.",
        ],
        Tx::FileDownloadFailed => [
            "خطا در دریافت فایل از تلگرام.",
            "Failed to download file from Telegram.",
            "Defectus in fasciculo ex Telegram accipiendo.",
            "从 Telegram 下载文件失败。",
            "Ошибка загрузки файла из Telegram.",
        ],
        Tx::FileSavedHeading => [
            "فایل در اینباکس ذخیره شد",
            "File saved to inbox",
            "Fasciculus in capsa servatus est",
            "文件已保存至收件箱",
            "Файл сохранён во входящие",
        ],
    };
    arr[lang.idx()]
}

/// Human-readable localized tier label (`User`, `Admin`, `Owner`).
pub fn tier_name(lang: Lang, tier: RoleTier) -> &'static str {
    match tier {
        RoleTier::User => t(lang, Tx::TierUser),
        RoleTier::Admin => t(lang, Tx::TierAdmin),
        RoleTier::Owner => t(lang, Tx::TierOwner),
    }
}

/// Compact badge + localized tier label.
pub fn tier_badge_name(lang: Lang, tier: RoleTier) -> String {
    format!("{} {}", tier.badge(), tier_name(lang, tier))
}

/// Localized display name for each of the 12 modular ACL keys.
pub fn perm_label<'a>(lang: Lang, perm: &'a str) -> &'a str {
    let arr: [&'a str; 5] = match perm {
        "dashboard_access" => ["داشبورد", "Dashboard", "Tabula", "仪表盘", "Панель"],
        "models_switch" => ["تغییر مدل", "Models", "Exemplaria", "模型切换", "Модели"],
        "uncensored" => ["بدون سانسور", "Uncensored", "Libera AI", "无审查", "Без цензуры"],
        "grok" => ["گراک", "Grok", "Grok", "Grok", "Grok"],
        "settings_access" => ["تنظیمات", "Settings", "Optiones", "设置", "Настройки"],
        "status_net" => ["وضعیت و شبکه", "Status/Net", "Status/Rete", "状态与网络", "Статус/Сеть"],
        "widgets" => ["ویجت‌ها", "Widgets", "Instrumenta", "小部件", "Виджеты"],
        "skills_manage" => ["مهارت‌ها", "Skills", "Artes", "技能管理", "Навыки"],
        "mcp_manage" => ["ابزارهای MCP", "MCPs", "MCP", "MCP 服务", "MCP"],
        "root_access" => ["دسترسی روت", "Root Access", "Root Access", "Root 权限", "Root-доступ"],
        "parallel" => ["حالت موازی", "Parallel", "Parallela", "并行模式", "Параллельно"],
        "automations" => ["اتوماسیون", "Automations", "Automata", "定时任务", "Автозадачи"],
        "sandbox_exec" => ["اجرای سندباکس", "Sandbox Exec", "Exsecutio Capsae", "沙箱执行", "Песочница"],
        _ => [perm, perm, perm, perm, perm],
    };
    arr[lang.idx()]
}

/// Slash command description in the user's selected language.
/// Guaranteed by unit test to be 3..=200 Unicode scalar values for Telegram `setMyCommands`.
pub fn cmd_description(lang: Lang, cmd: &str) -> &'static str {
    let arr: [&'static str; 5] = match cmd {
        "menu" => [
            "داشبورد یا کارت گفتگو",
            "Dashboard or chat card",
            "Tabula vel charta colloquii",
            "打开控制面板或对话卡片",
            "Панель или карточка чата",
        ],
        "new" => [
            "شروع گفتگوی تازه",
            "Start new chat",
            "Novum colloquium incipe",
            "开启全新对话会话",
            "Начать новый чат",
        ],
        "lang" => [
            "تغییر زبان ربات (۵ زبان)",
            "Switch language (5 languages)",
            "Muta linguam (V linguae)",
            "切换机器人语言（五种语言）",
            "Сменить язык (5 языков)",
        ],
        "model" => [
            "انتخاب مدل Antigravity",
            "Choose primary model",
            "Elige exemplar primarium",
            "选择主 AI 模型",
            "Выбрать модель Antigravity",
        ],
        "uncensored" => [
            "مدل و ایجنت بدون سانسور ونیس",
            "Venice Uncensored agent & models",
            "Venice Libera agens et exemplaria",
            "Venice 无审查模型与智能体",
            "Venice Без цензуры и модели",
        ],
        "uagent" => [
            "اجرای ایجنت خودمختار بدون سانسور",
            "Run Uncensored autonomous agent",
            "Age agentem liberum autonomum",
            "运行无审查自主智能体",
            "Запуск автономного агента без цензуры",
        ],
        "grok" => [
            "پنل و مدل‌های گراک",
            "Grok models & OAuth panel",
            "Tabula et exemplaria Grok",
            "Grok 模型与订阅控制面板",
            "Панель и модели Grok",
        ],
        "gagent" => [
            "اجرای ایجنت خودمختار گراک",
            "Run Grok autonomous agent",
            "Age agentem Grok autonomum",
            "运行 Grok 自主智能体",
            "Запуск автономного агента Grok",
        ],
        "stop" => [
            "توقف تسک در حال اجرا",
            "Stop current task",
            "Siste opus currens",
            "停止当前运行任务",
            "Остановить текущую задачу",
        ],
        "parallel" => [
            "اجرای موازی چند ایجنت",
            "Parallel agents: /parallel 2|3|off",
            "Agentes paralleli: /parallel 2|3|off",
            "多智能体并行模式设置",
            "Параллельные агенты: 2|3|off",
        ],
        "auto" => [
            "اتوماسیون و زمان‌بندی دستورات",
            "Scheduled automations",
            "Automata temporaria",
            "管理定时自动化任务",
            "Автоматизации по расписанию",
        ],
        "status" => [
            "وضعیت سرور و موتور",
            "Server & engine status",
            "Status servitoris et machinae",
            "查看服务器与引擎状态",
            "Статус сервера и движка",
        ],
        "mcp" => [
            "مدیریت سرورهای MCP",
            "Manage MCP servers",
            "Procura servitores MCP",
            "管理 MCP 工具服务器",
            "Управление серверами MCP",
        ],
        "skills" => [
            "مرور و مدیریت مهارت‌ها",
            "Browse & manage skills",
            "Inspice et procura artes",
            "浏览与管理技能库",
            "Просмотр и управление навыками",
        ],
        "skillhub" => [
            "جستجو و مرور اکوسیستم Skill Hub",
            "Search Skill Hub & Superpowers",
            "Quaere Skill Hub et Superpowers",
            "搜索 Skill Hub 与 Superpowers",
            "Поиск в Skill Hub и Superpowers",
        ],
        "settings" => [
            "حالت، تلاش و تنظیمات رندر",
            "Mode, effort & rendering",
            "Modus, vis et optiones",
            "调整模式、推理深度与渲染",
            "Режим, глубина и отображение",
        ],
        "effort" => [
            "تنظیم عمق استدلال مدل",
            "Reasoning effort: /effort high",
            "Vis ratiocinandi: /effort high",
            "设置模型推理深度等级",
            "Глубина рассуждений модели",
        ],
        "mode" => [
            "تنظیم حالت ایجنت (plan/agent)",
            "Agent mode: /mode plan",
            "Modus agentis: /mode plan",
            "切换智能体运行模式",
            "Режим агента (/mode plan)",
        ],
        "resume" => [
            "ادامه یا انتخاب نشست‌های قبلی",
            "Resume a saved session",
            "Resumere sessionem servatam",
            "恢复历史对话会话",
            "Продолжить прошлую сессию",
        ],
        "cwd" => [
            "نمایش یا تغییر پوشه کاری",
            "Workspace folder",
            "Directorium officinae",
            "查看或切换工作目录",
            "Рабочая директория",
        ],
        "agent" => [
            "تنظیم ایجنت سفارشی",
            "Custom agent preset",
            "Agens proprius",
            "选择或清除自定义智能体",
            "Пользовательский агент",
        ],
        "trace" => [
            "نمایش یا مخفی‌سازی رد ابزارها",
            "Toggle tool trace",
            "Commuta vestigium instrumentorum",
            "开关工具调用追踪显示",
            "Показать или скрыть трассировку",
        ],
        "changelog" => [
            "مشاهده تغییرات نسخه agy",
            "View agy release notes",
            "Vide notas editionis agy",
            "查看 agy 版本更新日志",
            "Посмотреть список изменений agy",
        ],
        "net" => [
            "بررسی سلامت شبکه و پروکسی",
            "Connection & proxy health",
            "Valetudo retis et vicarii",
            "检查网络连接与代理状态",
            "Состояние сети и прокси",
        ],
        "proxies" => [
            "مدیریت پروکسی‌های اختصاصی و سلامت آن‌ها",
            "Manage sticky proxies & health",
            "Procura vicarios et valetudinem",
            "管理专属代理池与健康状态",
            "Управление прокси и проверкой",
        ],
        "cron" => [
            "وضعیت وظایف همگام‌سازی زمان‌بندی",
            "Scheduled sync jobs",
            "Opera synchronizationis",
            "查看定时同步任务状态",
            "Запланированные задачи синхронизации",
        ],
        "widget" => [
            "ویجت‌های تعاملی تلگرام ۱۰.۴",
            "Interactive HTML widgets (10.4)",
            "Instrumenta HTML interactiva",
            "打开交互式 HTML 小部件",
            "Интерактивные виджеты (10.4)",
        ],
        "cancel" => [
            "لغو عملیات در حال انتظار",
            "Cancel pending input",
            "Abroga ingressum exspectantem",
            "取消当前等待的输入操作",
            "Отменить текущий ввод",
        ],
        "help" => [
            "راهنما و فهرست دستورات فعال",
            "Help & available commands",
            "Auxilium et index mandatorum",
            "查看帮助与可用命令列表",
            "Справка и доступные команды",
        ],
        "users" => [
            "مدیریت کاربران، سطوح و ماژول‌ها",
            "Users, tiers & module access",
            "Usores, gradus et moduli",
            "管理用户、权限等级与模块",
            "Управление пользователями и правами",
        ],
        "accounts" => [
            "مدیریت اکانت‌های Antigravity",
            "Antigravity account pool & OAuth",
            "Rationes Antigravity et failover",
            "管理 Antigravity 账号池与切换",
            "Пул аккаунтов Antigravity",
        ],
        "secretary" => [
            "حالت منشی هوشمند تلگرام بیزینس",
            "Secretary Mode (Telegram Business)",
            "Modus Scribae (Telegram Business)",
            "管理商业智能秘书模式",
            "Режим секретаря Telegram Business",
        ],
        "updates" => [
            "مدیریت آپدیت ماژولار اسکیل‌ها و MCP",
            "Modular skills & MCP auto-updater",
            "Renovator modularis artium et MCP",
            "模块化技能与 MCP 自动更新",
            "Модульное обновление навыков и MCP",
        ],
        _ => [
            "فرمان ربات آنتی‌گراویتی",
            "Bot command",
            "Mandatum instrumenti",
            "机器人功能命令",
            "Команда бота",
        ],
    };
    arr[lang.idx()]
}

/// Resolves the active [`Lang`] directly from `AclStore` and `StateStore`.
pub fn lang_for(acl: &AclStore, store: &StateStore, uid: i64) -> Lang {
    if let Some(code) = store
        .get_user(uid)
        .extra
        .get("lang")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
    {
        if let Some(l) = Lang::from_code(&code) {
            return l;
        }
    }
    if let Some(tg_code) = acl.get_user(uid).and_then(|u| u.language_code) {
        if let Some(l) = Lang::from_tg_language_code(&tg_code) {
            return l;
        }
    }
    Lang::En
}

/// Resolves the active [`Lang`] for `uid`:
/// stored `u.extra["lang"]` -> ACL Telegram `language_code` -> `Lang::En`.
pub fn user_lang(ctx: &BotCtx, uid: i64) -> Lang {
    lang_for(&ctx.acl, &ctx.store, uid)
}

/// Owner's preferred UI language (for startup/admin alerts).
pub fn owner_lang(ctx: &BotCtx) -> Lang {
    user_lang(ctx, ctx.cfg.owner_id)
}

/// Persists `uid`'s selected UI language in `UserState.extra["lang"]`.
pub fn set_user_lang(ctx: &BotCtx, uid: i64, lang: Lang) -> agy_core::Result<()> {
    ctx.store.update_user(uid, |u| {
        u.extra.insert("lang".to_string(), json!(lang.code()));
    })?;
    Ok(())
}

/// Formats a localized `[module required]` denial card.
pub fn missing_perm_html(ctx: &BotCtx, uid: i64, perm: &str) -> String {
    let lang = user_lang(ctx, uid);
    format!(
        "{} <b>{}</b> <code>{}</code>",
        ctx.e("lock"),
        t(lang, Tx::ModuleRequiredHdr),
        perm_label(lang, perm),
    )
}

/// Formats a localized Owner-only denial message.
pub fn owner_only_html(ctx: &BotCtx, uid: i64) -> String {
    let lang = user_lang(ctx, uid);
    format!("{} {}", ctx.e("lock"), t(lang, Tx::OwnerOnly))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CMDS: &[&str] = &[
        "menu",
        "new",
        "lang",
        "model",
        "uncensored",
        "uagent",
        "grok",
        "gagent",
        "stop",
        "parallel",
        "auto",
        "status",
        "mcp",
        "skills",
        "skillhub",
        "settings",
        "effort",
        "mode",
        "resume",
        "cwd",
        "agent",
        "trace",
        "changelog",
        "net",
        "proxies",
        "cron",
        "widget",
        "cancel",
        "help",
        "users",
        "accounts",
        "secretary",
        "updates",
    ];

    #[test]
    fn all_command_descriptions_meet_telegram_length_constraints() {
        for &lang in &Lang::ALL {
            for &cmd in ALL_CMDS {
                let desc = cmd_description(lang, cmd);
                let len = desc.chars().count();
                assert!(
                    (3..=200).contains(&len),
                    "Telegram setMyCommands requires 3..=256 chars; lang={:?} cmd={} desc={:?} len={}",
                    lang,
                    cmd,
                    desc,
                    len
                );
            }
        }
    }

    #[test]
    fn language_code_parsing_covers_all_five_locales() {
        assert_eq!(Lang::from_code("fa"), Some(Lang::Fa));
        assert_eq!(Lang::from_code("fa-IR"), Some(Lang::Fa));
        assert_eq!(Lang::from_code("en_US"), Some(Lang::En));
        assert_eq!(Lang::from_code("la"), Some(Lang::La));
        assert_eq!(Lang::from_code("zh-hans"), Some(Lang::Zh));
        assert_eq!(Lang::from_code("ru-RU"), Some(Lang::Ru));
        assert_eq!(Lang::from_code("de"), None);
        assert!(Lang::Fa.is_rtl());
        assert!(!Lang::En.is_rtl());
    }
}
