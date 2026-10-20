/** Инициализация JWT до монтирования панелей (избегаем запросов без Bearer). */
export default defineNuxtPlugin(async () => {
  const auth = useUiAuth()
  await auth.init()
})
