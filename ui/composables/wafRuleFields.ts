/** Справочник полей condition_json / transform_json для конструктора WAF. */

export type ConditionFieldId =
  | 'method'
  | 'path_exact'
  | 'path_prefix'
  | 'path_contains'
  | 'path_regex'
  | 'request_uri_contains'
  | 'body_contains'
  | 'header_contains'
  | 'query_equals'
  | 'client_ip_in'
  | 'client_ip_not_in'

export type ConditionBlock = {
  id: string
  field: ConditionFieldId
  value: string
  headerKey?: string
  headerVal?: string
  queryKey?: string
  queryVal?: string
}

export type TransformFields = {
  redirect_url: string
  replace_from: string
  replace_to: string
}

export const WAF_ACTIONS = [
  { id: 'block', label: 'block — заблокировать запрос', terminal: true },
  { id: 'allow', label: 'allow — явно разрешить (остановить цепочку)', terminal: true },
  { id: 'log', label: 'log — только записать в журнал', terminal: false },
  { id: 'redirect', label: 'redirect — HTTP-редирект', terminal: true },
  { id: 'replace', label: 'replace — замена фрагмента тела', terminal: true },
] as const

export const CONDITION_FIELDS: {
  id: ConditionFieldId
  label: string
  jsonKey: string
  description: string
  example: string
  valueLabel?: string
  placeholder?: string
  multiline?: boolean
}[] = [
  {
    id: 'method',
    label: 'HTTP-метод',
    jsonKey: 'method',
    description: 'Срабатывает только для указанного метода (GET, POST, …). Сравнение без учёта регистра.',
    example: '{ "method": "POST" }',
    valueLabel: 'Метод',
    placeholder: 'POST',
  },
  {
    id: 'path_exact',
    label: 'Точный путь',
    jsonKey: 'path_exact',
    description: 'Путь запроса (без query) должен совпасть полностью, например /api/login.',
    example: '{ "path_exact": "/api/login" }',
    placeholder: '/api/login',
  },
  {
    id: 'path_prefix',
    label: 'Префикс пути',
    jsonKey: 'path_prefix',
    description: 'Путь начинается с указанной строки (path starts with). Удобно для целых веток API.',
    example: '{ "path_prefix": "/admin/" }',
    placeholder: '/admin/',
  },
  {
    id: 'path_contains',
    label: 'Подстрока в пути',
    jsonKey: 'path_contains',
    description: 'В пути (без query) должна встретиться подстрока.',
    example: '{ "path_contains": "/wp-admin" }',
    placeholder: '/wp-admin',
  },
  {
    id: 'path_regex',
    label: 'Путь (regex)',
    jsonKey: 'path_regex',
    description: 'Путь проверяется регулярным выражением Go (RE2). Ошибка в regex ломает компиляцию политики.',
    example: '{ "path_regex": "^/api/v[0-9]+/" }',
    placeholder: '^/api/v[0-9]+/',
  },
  {
    id: 'request_uri_contains',
    label: 'Подстрока в Request-URI',
    jsonKey: 'request_uri_contains',
    description: 'Проверка по полному Request-URI (путь + ?query), как в строке запроса.',
    example: '{ "request_uri_contains": "password=" }',
    placeholder: 'password=',
  },
  {
    id: 'body_contains',
    label: 'Подстрока в теле',
    jsonKey: 'body_contains',
    description: 'В теле HTTP-запроса (после чтения на шлюзе) должна быть подстрока. Большие тела ограничены лимитом сканера.',
    example: '{ "body_contains": "<script" }',
    placeholder: '<script',
  },
  {
    id: 'header_contains',
    label: 'Заголовок содержит',
    jsonKey: 'header_contains',
    description: 'Объект: имя заголовка → подстрока в значении (без учёта регистра значения). Можно добавить несколько блоков с разными заголовками.',
    example: '{ "header_contains": { "User-Agent": "curl" } }',
  },
  {
    id: 'query_equals',
    label: 'Query-параметр',
    jsonKey: 'query_equals',
    description: 'Первое значение query-параметра должно точно совпасть.',
    example: '{ "query_equals": { "debug": "1" } }',
  },
  {
    id: 'client_ip_in',
    label: 'Клиентский IP в списке',
    jsonKey: 'client_ip_in',
    description:
      'IP клиента (с учётом X-Forwarded-For при настроенных доверенных прокси) должен попасть в один из CIDR/IP. Иначе правило пропускается.',
    example: '{ "client_ip_in": ["10.0.0.0/8", "192.168.0.1"] }',
    multiline: true,
    placeholder: '10.0.0.0/8\n192.168.0.1',
  },
  {
    id: 'client_ip_not_in',
    label: 'Клиентский IP НЕ в списке',
    jsonKey: 'client_ip_not_in',
    description:
      'Если IP клиента в списке — правило не срабатывает. Удобно для «блокировать всех, кроме доверенных сетей».',
    example: '{ "path_prefix": "/api/", "client_ip_not_in": ["10.0.0.0/8"] }',
    multiline: true,
    placeholder: '10.0.0.0/8',
  },
]

export const TRANSFORM_FIELDS = [
  {
    id: 'redirect_url',
    label: 'redirect_url',
    description: 'URL для ответа 302 при action=redirect. Обязателен для redirect.',
    example: '{ "redirect_url": "https://example.com/blocked" }',
  },
  {
    id: 'replace_from',
    label: 'replace_from / replace_to',
    description: 'Замена подстроки в теле запроса при action=replace (простая подстановка).',
    example: '{ "replace_from": "old", "replace_to": "new" }',
  },
] as const

export const RUNTIME_VARIABLES = [
  {
    name: '{REMOTE_ADDR}',
    description: 'В шаблонах документации: IP клиента. В condition_json используйте client_ip_in / client_ip_not_in.',
  },
  {
    name: '{REQUEST_URI}',
    description: 'Полный URI запроса — аналог проверки request_uri_contains.',
  },
  {
    name: 'client_ip',
    description: 'Эффективный IP после разбора доверенных прокси (WAF_TRUSTED_PROXIES). Пишется в журнал как source_ip.',
  },
] as const
