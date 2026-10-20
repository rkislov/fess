export const UI_THEME_STORAGE_KEY = 'fess-ui-theme'

export type UiThemePreference = 'light' | 'dark' | 'system'
export type UiThemeResolved = 'light' | 'dark'

export function parseUiThemePreference(raw: string | null): UiThemePreference {
  if (raw === 'light' || raw === 'dark' || raw === 'system') return raw
  return 'system'
}

export function systemPrefersDark(): boolean {
  if (!import.meta.client) return true
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

export function resolveUiTheme(pref: UiThemePreference): UiThemeResolved {
  if (pref === 'system') return systemPrefersDark() ? 'dark' : 'light'
  return pref
}

export function applyResolvedUiTheme(resolved: UiThemeResolved) {
  if (!import.meta.client) return
  const root = document.documentElement
  root.classList.toggle('theme-dark', resolved === 'dark')
  root.classList.toggle('theme-light', resolved === 'light')
  root.style.colorScheme = resolved
}

export function useUiTheme() {
  const preference = useState<UiThemePreference>('ui-theme-pref', () => {
    if (!import.meta.client) return 'system'
    return parseUiThemePreference(localStorage.getItem(UI_THEME_STORAGE_KEY))
  })
  const mediaEpoch = useState('ui-theme-mq', () => 0)

  const resolved = computed(() => {
    void mediaEpoch.value
    return resolveUiTheme(preference.value)
  })

  function persist() {
    if (!import.meta.client) return
    localStorage.setItem(UI_THEME_STORAGE_KEY, preference.value)
    applyResolvedUiTheme(resolved.value)
  }

  function setPreference(next: UiThemePreference) {
    preference.value = next
    persist()
  }

  function hydrate() {
    if (!import.meta.client) return
    preference.value = parseUiThemePreference(localStorage.getItem(UI_THEME_STORAGE_KEY))
    applyResolvedUiTheme(resolved.value)
  }

  function onSystemSchemeChange() {
    mediaEpoch.value++
    applyResolvedUiTheme(resolveUiTheme(preference.value))
  }

  return { preference, resolved, setPreference, hydrate, onSystemSchemeChange }
}
