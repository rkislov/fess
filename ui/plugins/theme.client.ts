import { useUiTheme } from '~/composables/useUiTheme'

export default defineNuxtPlugin(() => {
  const { hydrate, preference, onSystemSchemeChange } = useUiTheme()
  hydrate()

  const mq = window.matchMedia('(prefers-color-scheme: dark)')
  const onChange = () => {
    if (preference.value === 'system') onSystemSchemeChange()
  }
  mq.addEventListener('change', onChange)
})
