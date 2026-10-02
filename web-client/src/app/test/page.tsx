'use client'

import { useEffect, useState } from 'react'
import { getTokenFromCookie, decodeJWT, isTokenValid, hasUIAccess } from '@/utils/auth'

export default function TestPage() {
  const [tokenInfo, setTokenInfo] = useState<any>(null)
  const [bypassAuth, setBypassAuth] = useState(false)
  const [cookies, setCookies] = useState<string>('')

  useEffect(() => {
    setCookies(document.cookie)

    const token = getTokenFromCookie()
    if (token) {
      const payload = decodeJWT(token)
      const valid = isTokenValid(token)
      const uiAccess = hasUIAccess(token)
      setTokenInfo({
        token: token.substring(0, 50) + '...',
        payload,
        valid,
        uiAccess,
        cookies: document.cookie,
        timestamp: new Date().toISOString()
      })
    } else {
      setTokenInfo({
        token: null,
        payload: null,
        valid: false,
        uiAccess: false,
        cookies: document.cookie,
        timestamp: new Date().toISOString()
      })
    }
  }, [])

  return (
    <main className="p-8">
      <h1 className="text-2xl font-bold mb-4">Authentication Test</h1>

      <div className="mb-4">
        <label className="flex items-center">
          <input
            type="checkbox"
            checked={bypassAuth}
            onChange={(e) => setBypassAuth(e.target.checked)}
            className="mr-2"
          />
          Bypass Authentication (for testing)
        </label>
      </div>

      <div className="mb-4">
        <h2 className="text-lg font-semibold mb-2">Token Information:</h2>
        <pre className="bg-gray-100 p-4 rounded overflow-auto text-sm">
          {JSON.stringify(tokenInfo, null, 2)}
        </pre>
      </div>

      <div className="mb-4">
        <h2 className="text-lg font-semibold mb-2">Quick Tests:</h2>
        <div className="space-y-2">
          <div>
            <strong>Token Found:</strong> {tokenInfo?.token ? 'Yes' : 'No'}
          </div>
          <div>
            <strong>Token Valid:</strong> {tokenInfo?.valid ? 'Yes' : 'No'}
          </div>
          <div>
            <strong>UI Access:</strong> {tokenInfo?.uiAccess ? 'Yes' : 'No'}
          </div>
          <div>
            <strong>Username:</strong> {tokenInfo?.payload?.sub || 'None'}
          </div>
          <div>
            <strong>Role:</strong> {tokenInfo?.payload?.role || 'None'}
          </div>
          <div>
            <strong>UI Access in Token:</strong> {tokenInfo?.payload?.accesses?.ui_access ? 'Yes' : 'No'}
          </div>
        </div>
      </div>

      <div className="mb-4">
        <h2 className="text-lg font-semibold mb-2">All Cookies:</h2>
        <pre className="bg-gray-100 p-4 rounded overflow-auto text-sm">
          {cookies || 'No cookies found'}
        </pre>
      </div>
    </main>
  )
}
