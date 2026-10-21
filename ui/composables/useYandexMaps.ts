// A unique namespace per key allows changing browser keys without reusing an
// already initialized SDK. Failed requests can be retried on the next refresh.
const loaders = new Map<string, Promise<any>>()
let sequence = 0
export function loadYandexMaps(key: string): Promise<any> {
  const cached = loaders.get(key)
  if (cached) return cached
  const namespace = `fessYmaps${++sequence}`
  const promise = new Promise<any>((resolve, reject) => {
    const script = document.createElement('script')
    const timer = setTimeout(() => fail(), 15000)
    function fail() {
      clearTimeout(timer)
      script.remove()
      loaders.delete(key)
      reject(new Error('Не удалось загрузить Яндекс Карты. Проверьте ключ и доступ к API.'))
    }
    script.src = `https://api-maps.yandex.ru/2.1/?apikey=${encodeURIComponent(key)}&lang=ru_RU&ns=${namespace}`
    script.onerror = fail
    script.onload = () => {
      const sdk = (window as any)[namespace]
      if (!sdk) { fail(); return }
      sdk.ready(() => { clearTimeout(timer); resolve(sdk) }, fail)
    }
    document.head.appendChild(script)
  })
  loaders.set(key, promise)
  return promise
}
